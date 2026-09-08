"""Experimental socket negotiation using permutations of complete covertexts.

The public entry point is ``fteproxy.wrap_socket(negotiation='permutation')``.
See docs/permutation-bootstrap.md for the wire protocol and its assumptions.
"""

import hashlib
import hmac
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass

import fte

from fteproxy import _make_body_cipher, record_layer
from fteproxy import bootstrap


_OFFER = struct.Struct('>BBHH')  # version, mode, downstream bytes, upstream regex bytes
_MODES = ('format', 'hybrid')
_CONTROL_BYTES = 16
_MIN_CAPACITY = record_layer._SEAL_OVERHEAD + _CONTROL_BYTES
_READ_SIZE = 65536
_HANDSHAKE_TIMEOUT = 5.0


class HandshakeError(ConnectionError):
    """An invalid, incomplete, or incompatible negotiation; the socket is closed."""


@dataclass(frozen=True)
class Parameters:
    """Negotiated directions are always relative to the client."""

    upstream_regex: str
    upstream_length: int
    downstream_regex: str
    downstream_length: int
    mode: str

    def encode(self):
        if self.mode not in _MODES:
            raise ValueError('record_layer_mode must be format or hybrid')
        for length in (self.upstream_length, self.downstream_length):
            if type(length) is not int or not 1 <= length <= bootstrap.MAX_WORD_BYTES:
                raise ValueError('permutation covertext lengths must be 1..512 bytes')
        if not all(isinstance(pattern, str) and pattern for pattern in
                   (self.upstream_regex, self.downstream_regex)):
            raise ValueError('both regexes must be nonempty strings')
        upstream = self.upstream_regex.encode('utf-8')
        downstream = self.downstream_regex.encode('utf-8')
        if len(upstream) + len(downstream) > bootstrap.MAX_DESCRIPTION - _OFFER.size:
            raise ValueError('combined UTF-8 regex descriptions exceed 220 bytes')
        return (_OFFER.pack(1, _MODES.index(self.mode), self.downstream_length,
                            len(upstream)) + upstream + downstream)

    @classmethod
    def decode(cls, description, upstream_length):
        if len(description) < _OFFER.size:
            raise ValueError('truncated permutation offer')
        version, mode, downstream_length, split = _OFFER.unpack_from(description)
        patterns = description[_OFFER.size:]
        if version != 1 or mode >= len(_MODES) or not 0 < split < len(patterns):
            raise ValueError('invalid permutation offer')
        result = cls(patterns[:split].decode('utf-8'), upstream_length,
                     patterns[split:].decode('utf-8'), downstream_length, _MODES[mode])
        result.encode()  # Apply the same length and text bounds on both endpoints.
        return result


def _derive(key, label, context):
    return hmac.digest(key, b'fteproxy/permutation/v1/' + label + b'\0' + context,
                       'sha256')


def _compile(parameters, key):
    """Called on the server only after the entire offer authenticates.

    Patterns are trusted input from a key holder. The descriptor byte bound
    does not bound DFA construction time or memory.
    """
    try:
        formats = (fte.RegexFormat(parameters.upstream_regex, length=parameters.upstream_length),
                   fte.RegexFormat(parameters.downstream_regex, length=parameters.downstream_length))
        for fmt in formats:
            if fte.FTE(key=key, output_format=fmt).max_plaintext_bytes < _MIN_CAPACITY:
                raise ValueError('each format must carry at least 28 FTE plaintext bytes')
    except fte.FTEError as error:
        raise ValueError('invalid or insufficient-capacity permutation format') from error
    return formats


class Socket:
    """A blocking FTE stream with lazy, mutually authenticated negotiation.

    One reader and one writer may run concurrently. A handshake timeout is
    terminal because a partially sent control record cannot safely be retried.
    ``recv`` preserves excess plaintext and rejects truncated final records.
    """

    def __init__(self, sock, key, outgoing_regex=None, outgoing_length=-1,
                 incoming_regex=None, incoming_length=-1, record_layer_mode=None):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError('permutation negotiation requires a 32-byte key')
        if record_layer_mode is not None and record_layer_mode not in _MODES:
            raise ValueError('record_layer_mode must be format or hybrid')
        if (outgoing_regex is None) != (incoming_regex is None):
            raise ValueError('supply both client regexes, or neither for the server')
        self._socket = sock
        self._key = key
        self._is_client = outgoing_regex is not None
        self._mode_constraint = record_layer_mode
        self.parameters = None
        self._formats = None
        if self._is_client:
            self.parameters = Parameters(outgoing_regex, outgoing_length,
                                         incoming_regex, incoming_length,
                                         record_layer_mode or 'format')
            self.parameters.encode()
            self._formats = _compile(self.parameters, key)
        elif outgoing_length != -1 or incoming_length != -1:
            raise ValueError('the server learns covertext lengths from the offer')
        self._ready = False
        self._failed = False
        self._handshake_lock = threading.Lock()
        self._read_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._plaintext = bytearray()

    def _set_deadline(self):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout('permutation handshake timed out')
        self._socket.settimeout(remaining)

    def _send_control(self, data):
        self._set_deadline()
        self._socket.sendall(data)

    def _read_control(self, length):
        result = bytearray()
        while len(result) < length:
            self._set_deadline()
            data = self._socket.recv(length - len(result))
            if not data:
                raise HandshakeError('peer closed during permutation negotiation')
            result.extend(data)
        return bytes(result)

    def _records(self, upstream_key, downstream_key):
        upstream, downstream = (fte.FTE(key=key, output_format=fmt)
                                for key, fmt in zip((upstream_key, downstream_key),
                                                    self._formats))
        up_body = _make_body_cipher(upstream_key) if self.parameters.mode == 'hybrid' else None
        down_body = _make_body_cipher(downstream_key) if self.parameters.mode == 'hybrid' else None
        if self._is_client:
            self._encoder = record_layer.Encoder(upstream, up_body)
            self._decoder = record_layer.Decoder(downstream, down_body)
            self._encoder._seq = 1  # Client confirmation used upstream position 0.
        else:
            self._encoder = record_layer.Encoder(downstream, down_body)
            self._decoder = record_layer.Decoder(upstream, up_body)
            self._decoder._seq = 1
        return upstream

    def _session(self, transcript, challenge):
        context = transcript + challenge
        upstream_key = _derive(self._key, b'client-to-server', context)
        downstream_key = _derive(self._key, b'server-to-client', context)
        upstream = self._records(upstream_key, downstream_key)
        finished = _derive(upstream_key, b'finished', context)[:_CONTROL_BYTES]
        return upstream, finished

    def _client_handshake(self):
        source = self._formats[0]
        words = [source.unrank(secrets.randbelow(source.cardinality))
                 for _ in range(bootstrap.BATCH_WORDS)]
        wire = bootstrap.encode(self._key, words, self.parameters.encode())
        transcript = hashlib.sha256(wire).digest()
        self._send_control(wire)
        acknowledgement = fte.FTE(key=_derive(self._key, b'ack', transcript),
                                  output_format=self._formats[1])
        record = self._read_control(self.parameters.downstream_length)
        challenge = record_layer._unseal(acknowledgement.decrypt(record), 0)
        if challenge is None or len(challenge) != _CONTROL_BYTES:
            raise HandshakeError('invalid server acknowledgement')
        upstream, finished = self._session(transcript, challenge)
        self._send_control(record_layer._seal(upstream, finished, 0))

    def _server_handshake(self):
        decoder = bootstrap.Decoder(self._key)
        result = None
        while result is None:
            self._set_deadline()
            data = self._socket.recv(_READ_SIZE)
            if not data:
                raise HandshakeError('peer closed during permutation negotiation')
            result = decoder.feed(data)
        if result.remainder:
            raise HandshakeError('client sent data before the server challenge')
        self.parameters = Parameters.decode(result.description, result.word_bytes)
        if self._mode_constraint is not None and self.parameters.mode != self._mode_constraint:
            raise HandshakeError('offered record-layer mode is not permitted')
        self._formats = _compile(self.parameters, self._key)
        challenge = secrets.token_bytes(_CONTROL_BYTES)
        acknowledgement = fte.FTE(key=_derive(self._key, b'ack', result.transcript_digest),
                                  output_format=self._formats[1])
        self._send_control(record_layer._seal(acknowledgement, challenge, 0))
        upstream, finished = self._session(result.transcript_digest, challenge)
        record = self._read_control(self.parameters.upstream_length)
        actual = record_layer._unseal(upstream.decrypt(record), 0)
        if actual is None or not hmac.compare_digest(actual, finished):
            raise HandshakeError('invalid client key confirmation')

    def do_handshake(self):
        """Negotiate once, with a five-second total network deadline.

        A shorter socket timeout takes precedence. Authenticated regex
        compilation is trusted work and is not preempted by this deadline.
        """
        with self._handshake_lock:
            if self._failed:
                raise HandshakeError('this permutation socket is closed or failed')
            if self._ready:
                return
            previous_timeout = self._socket.gettimeout()
            if previous_timeout == 0:
                raise ValueError('permutation sockets require blocking I/O')
            timeout = min(previous_timeout, _HANDSHAKE_TIMEOUT) if previous_timeout else _HANDSHAKE_TIMEOUT
            self._deadline = time.monotonic() + timeout
            try:
                if self._is_client:
                    self._client_handshake()
                else:
                    self._server_handshake()
                self._ready = True
            except socket.timeout:
                self.close()
                raise
            except (OSError, ValueError, fte.FTEError) as error:
                self.close()
                raise HandshakeError('permutation negotiation failed') from error
            finally:
                try:
                    self._socket.settimeout(previous_timeout)
                except OSError:
                    pass  # Failure closed the underlying descriptor.

    def _drain(self):
        decoded = self._decoder.pop()
        remaining = len(self._decoder._buffer)
        pending = self._decoder._pending_body_len
        needed = self._decoder._frame_size + (pending if pending is not None else 0)
        if remaining >= needed:
            self.close()
            raise ConnectionError('invalid or out-of-order FTE record')
        self._plaintext.extend(decoded)

    def recv(self, bufsize):
        if bufsize < 0:
            raise ValueError('negative buffersize in recv')
        if bufsize == 0:
            return b''
        self.do_handshake()
        with self._read_lock:
            while not self._plaintext:
                data = self._socket.recv(_READ_SIZE)
                if not data:
                    if self._decoder._buffer:
                        self.close()
                        raise ConnectionError('peer closed with a truncated FTE record')
                    return b''
                self._decoder.push(data)
                self._drain()
            result = bytes(self._plaintext[:bufsize])
            del self._plaintext[:bufsize]
            return result

    def send(self, data):
        data = bytes(data)
        self.do_handshake()
        with self._write_lock:
            # Bound encoded buffering even when the caller supplies a huge write.
            try:
                for offset in range(0, len(data), _READ_SIZE):
                    self._encoder.push(data[offset:offset + _READ_SIZE])
                    self._socket.sendall(self._encoder.pop())
            except OSError:
                self.close()  # Do not reuse sequence numbers after a partial write.
                raise
        return len(data)

    def sendall(self, data):
        self.send(data)

    def accept(self):
        connection, address = self._socket.accept()
        return Socket(connection, self._key, record_layer_mode=self._mode_constraint), address

    def close(self):
        self._failed = True
        self._socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # Delegate connection setup and socket options, never raw data operations.
    def fileno(self):
        return self._socket.fileno()

    def bind(self, address):
        return self._socket.bind(address)

    def listen(self, backlog=socket.SOMAXCONN):
        return self._socket.listen(backlog)

    def connect(self, address):
        return self._socket.connect(address)

    def settimeout(self, timeout):
        return self._socket.settimeout(timeout)

    def gettimeout(self):
        return self._socket.gettimeout()

    def setsockopt(self, *args):
        return self._socket.setsockopt(*args)

    def getsockopt(self, *args):
        return self._socket.getsockopt(*args)

    def getsockname(self):
        return self._socket.getsockname()

    def getpeername(self):
        return self._socket.getpeername()

    def shutdown(self, how):
        return self._socket.shutdown(how)
