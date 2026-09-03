#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__version__ = "0.4.0"

import os
import sys
import hmac
import functools
import socket
import hashlib
import traceback

import fteproxy.conf
import fteproxy.defs
import fteproxy.record_layer

import fte

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


@functools.lru_cache(maxsize=256)
def _make_cipher(pattern, length, key):
    """Build a libfte 0.4 cipher that hides bytes as one fixed-length covertext.

    ``pattern`` is the regex whose language the covertext is drawn from;
    ``length`` picks the fixed covertext length. This replaces libfte 0.3's
    ``fte.Encoder(regex, fixed_slice, key)``. The
    cipher ``encrypt``/``decrypt`` one whole covertext per call; the record
    layer handles stream chunking and framing on top of it.

    Cached. libfte 0.4 compiles the DFA afresh for every ``RegexFormat``
    (0.5 to 1.5 ms per format, and libfte 0.3 cached it globally), while
    fteproxy builds a cipher per socket and per negotiation attempt: that
    turned connection setup from about 3 ms into about 9 ms. An ``fte.FTE``
    holds only read-only tables and draws a fresh nonce on every call, so one
    instance serves every connection and thread.
    """
    return fte.FTE(
        output_format=fte.RegexFormat(pattern, length=length),
        key=key,
    )


def _hybrid_mode():
    """Whether the record layer runs in 'hybrid' (fast bulk) mode.

    'hybrid' (the default) formats only a fixed-length header per record and
    carries the body as raw authenticated bytes: much faster for bulk transfer,
    but everything past the header looks like random data. 'format' (opt-in)
    transforms every covertext byte into the target format for full-stream
    realism. See ``runtime.fteproxy.record_layer.mode`` in ``fteproxy.conf``.
    """
    return fteproxy.conf.getValue('runtime.fteproxy.record_layer.mode') == 'hybrid'


class _AEADBody:
    """AES-128-CTR + HMAC-SHA256 (Encrypt-then-MAC) carrier for hybrid-mode bodies.

    Matches libfte's AE construction (the FTE paper's CTR+HMAC). Under
    fteproxy's static shared key, Encrypt-then-MAC means a nonce collision costs
    only the confidentiality of the colliding pair, never authenticity. Each
    record binds its sequence number into the MAC, so a record reordered,
    dropped, or replayed within its stream fails authentication. The key is
    shared by every connection and both directions, so a record replayed at the
    same position of another stream is not detected (see SECURITY.md). The
    encryption and MAC subkeys are derived from a distinct namespace,
    domain-separated from the header cipher's key. libfte does the
    same construction for the formatted header; this is the raw-body counterpart
    the FTE paper appended as unformatted ciphertext.
    """
    _NONCE = 12
    _TAG = 16
    _COUNTER = 16  # AES block: 12-byte nonce || 4-byte block counter
    # Bytes a framed body (nonce || ciphertext || tag) adds to its plaintext.
    framing_overhead = _NONCE + _TAG
    # Largest body a single record carries. Bounds memory and amortizes the one
    # formatted header per record over a large payload.
    max_plaintext_bytes = 2 ** 20
    # Largest framed body a header may announce; the decoder refuses to buffer
    # more than this for one record.
    max_framed_bytes = max_plaintext_bytes + framing_overhead

    def __init__(self, key):
        self._enc_key = hashlib.sha256(key + b'fteproxy/record-layer/body/enc/v3').digest()[:16]
        self._mac_key = hashlib.sha256(key + b'fteproxy/record-layer/body/mac/v3').digest()

    def _counter(self, nonce):
        return nonce + b'\x00' * (self._COUNTER - self._NONCE)

    def _tag(self, seq, nonce, ciphertext):
        return hmac.new(
            self._mac_key, seq.to_bytes(8, 'big') + nonce + ciphertext, hashlib.sha256
        ).digest()[:self._TAG]

    def encrypt(self, plaintext, seq):
        nonce = os.urandom(self._NONCE)
        enc = Cipher(algorithms.AES(self._enc_key), modes.CTR(self._counter(nonce))).encryptor()
        ciphertext = enc.update(plaintext) + enc.finalize()
        return nonce + ciphertext + self._tag(seq, nonce, ciphertext)

    def decrypt(self, framed, seq):
        nonce = framed[:self._NONCE]
        tag = framed[-self._TAG:]
        ciphertext = framed[self._NONCE:-self._TAG]
        if not hmac.compare_digest(self._tag(seq, nonce, ciphertext), tag):
            raise InvalidTag()
        dec = Cipher(algorithms.AES(self._enc_key), modes.CTR(self._counter(nonce))).decryptor()
        return dec.update(ciphertext) + dec.finalize()


def _make_body_cipher(key):
    """The AEAD carrier for hybrid-mode record bodies (see :class:`_AEADBody`)."""
    return _AEADBody(key)


def _record_encoder(header_cipher, key):
    body = _make_body_cipher(key) if _hybrid_mode() else None
    return fteproxy.record_layer.Encoder(cipher=header_cipher, body_cipher=body)


def _record_decoder(header_cipher, key):
    body = _make_body_cipher(key) if _hybrid_mode() else None
    return fteproxy.record_layer.Decoder(cipher=header_cipher, body_cipher=body)


class InvalidRoleException(Exception):
    pass


class NegotiationFailedException(Exception):
    pass


class ChannelNotReadyException(Exception):
    pass


class NegotiateTimeoutException(Exception):

    """Raised when negotiation fails to complete after """ + str(fteproxy.conf.getValue('runtime.fteproxy.negotiate.timeout')) + """ seconds.
    """
    pass


def fatal_error(msg):
    if fteproxy.conf.getValue('runtime.loglevel') in [1,2,3]:
        print('ERROR:', msg)
    sys.exit(1)


def warn(msg):
    if fteproxy.conf.getValue('runtime.loglevel') in [2,3]:
        print('WARN:', msg)


def info(msg):
    if fteproxy.conf.getValue('runtime.loglevel') in [3]:
        print('INFO:', msg)


class NegotiateCell(object):
    _CELL_SIZE = 64
    _PADDING_LEN = 32
    _PADDING_CHAR = b'\x00'
    _DATE_FORMAT = b'YYYYMMDD'

    def __init__(self):
        self._def_file = b""
        self._language = b""

    def setDefFile(self, def_file):
        if isinstance(def_file, str):
            def_file = def_file.encode('utf-8')
        self._def_file = def_file

    def getDefFile(self):
        if isinstance(self._def_file, bytes):
            return self._def_file.decode('utf-8')
        return self._def_file

    def setLanguage(self, language):
        if isinstance(language, str):
            language = language.encode('utf-8')
        self._language = language

    def getLanguage(self):
        if isinstance(self._language, bytes):
            return self._language.decode('utf-8')
        return self._language

    def toBytes(self):
        retval = b''
        retval += self._def_file
        retval += self._language
        retval = retval.rjust(NegotiateCell._CELL_SIZE, NegotiateCell._PADDING_CHAR)
        assert retval[:NegotiateCell._PADDING_LEN] == NegotiateCell._PADDING_CHAR * \
            NegotiateCell._PADDING_LEN
        return retval

    def fromBytes(self, negotiate_cell_bytes):
        assert len(negotiate_cell_bytes) == NegotiateCell._CELL_SIZE
        assert negotiate_cell_bytes[
            :NegotiateCell._PADDING_LEN] == NegotiateCell._PADDING_CHAR * NegotiateCell._PADDING_LEN
        negotiate_cell_bytes = negotiate_cell_bytes.strip(
            NegotiateCell._PADDING_CHAR)
        # 8==len(YYYYMMDD)
        def_file = negotiate_cell_bytes[:len(NegotiateCell._DATE_FORMAT)]
        language = negotiate_cell_bytes[len(NegotiateCell._DATE_FORMAT):]
        negotiate_cell = NegotiateCell()
        negotiate_cell.setDefFile(def_file)
        negotiate_cell.setLanguage(language)
        return negotiate_cell


class NegotiationManager(object):

    def __init__(self, K1, K2):
        self._negotiationComplete = False
        self._K1 = K1
        self._K2 = K2
        self._maxNegotiationBytes = None

    def _key(self):
        # libfte 0.4 requires an explicit 32-byte key; the old "key=None means
        # generate a random key" path is gone (and never interoperated across a
        # client/server pair anyway). Fall back to the configured shared key.
        if self._K1 and self._K2:
            return self._K1 + self._K2
        return fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')

    def getNegotiationComplete(self):
        return self._negotiationComplete

    def getMaxNegotiationBytes(self):
        """The most bytes a client's negotiation record can occupy on the wire.

        The record is one sealed covertext of the request format's fixed
        ``length`` (the 64-byte cell fits in a single covertext of every
        built-in format), followed in hybrid mode by the framed cell. Whatever
        the client's format, its record therefore fits in this many bytes, so
        a server only ever needs to scan, or keep, that much from a peer that
        has not negotiated: once more has arrived without a record decoding,
        the peer never will.
        """
        if self._maxNegotiationBytes is None:
            languages = fteproxy.defs.load_definitions()
            longest = max(fteproxy.defs.getLength(language)
                          for language in languages
                          if language.endswith('-request'))
            if _hybrid_mode():
                longest += NegotiateCell._CELL_SIZE + _AEADBody.framing_overhead
            self._maxNegotiationBytes = longest
        return self._maxNegotiationBytes

    def _acceptNegotiation(self, data):

        languages = fteproxy.defs.load_definitions()

        # Try the configured upstream language first. The server otherwise scans
        # request-languages in definition order and attempts a decode against
        # each until one succeeds; the default is near the end of that list, so
        # every connection pays ~20 failed decodes before matching. A client and
        # server sharing config (the common case) now match on the first try,
        # while non-default clients still fall through to the full scan.
        preferred = fteproxy.conf.getValue('runtime.state.upstream_language')
        scan_order = ([preferred] if preferred in languages else []) + \
            [lang for lang in languages.keys() if lang != preferred]

        for incoming_language in scan_order:
            try:
                if incoming_language.endswith('response'):
                    continue

                incoming_regex = fteproxy.defs.getRegex(incoming_language)
                incoming_length = fteproxy.defs.getLength(
                    incoming_language)

                key = self._key()
                incoming_cipher = _make_cipher(incoming_regex, incoming_length, key)
                decoder = _record_decoder(incoming_cipher, key)

                decoder.push(data)
                negotiate_cell = decoder.pop(oneCell=True)
                NegotiateCell().fromBytes(negotiate_cell)

                return [negotiate_cell, decoder._buffer]
            except Exception as e:
                fteproxy.info('Failed to decode first message as '+incoming_language+': '+str(e))

        raise NegotiationFailedException()

    def _init_encoders(self,
                       outgoing_regex, outgoing_length,
                       incoming_regex, incoming_length):

        encoder = None
        decoder = None

        key = self._key()

        if outgoing_regex != None and outgoing_length != -1:
            outgoing_cipher = _make_cipher(outgoing_regex, outgoing_length, key)
            encoder = _record_encoder(outgoing_cipher, key)

        if incoming_regex != None and incoming_length != -1:
            incoming_cipher = _make_cipher(incoming_regex, incoming_length, key)
            decoder = _record_decoder(incoming_cipher, key)

        return [encoder, decoder]

    def _makeNegotiationCell(self, encoder):
        negotiate_cell = NegotiateCell()
        def_file = fteproxy.conf.getValue('fteproxy.defs.release')
        negotiate_cell.setDefFile(def_file)
        language = fteproxy.conf.getValue('runtime.state.upstream_language')
        language = language[:-len('-request')]
        negotiate_cell.setLanguage(language)
        encoder.push(negotiate_cell.toBytes())
        data = encoder.pop()
        return data

    def makeClientNegotiationCell(self,
                                  outgoing_regex, outgoing_length,
                                  incoming_regex, incoming_length):
        [encoder, decoder] = self._init_encoders(
            outgoing_regex, outgoing_length, incoming_regex, incoming_length)
        return self._makeNegotiationCell(encoder)

    def doServerSideNegotiation(self, data):
        [negotiate_cell, remaining_buffer] = self._acceptNegotiation(data)

        negotiate = NegotiateCell().fromBytes(negotiate_cell)

        outgoing_language = negotiate.getLanguage() + '-response'
        incoming_language = negotiate.getLanguage() + '-request'

        outgoing_regex = fteproxy.defs.getRegex(outgoing_language)
        outgoing_length = fteproxy.defs.getLength(outgoing_language)
        incoming_regex = fteproxy.defs.getRegex(incoming_language)
        incoming_length = fteproxy.defs.getLength(incoming_language)

        [encoder, decoder] = self._init_encoders(
            outgoing_regex, outgoing_length, incoming_regex, incoming_length)

        decoder.push(remaining_buffer)

        return [encoder, decoder]


class FTEHelper(object):

    def _processRecv(self, data):
        retval = data
        if self._isServer and not self._negotiationComplete:
            limit = self._negotiation_manager.getMaxNegotiationBytes()
            # A valid negotiation record fits in the first ``limit`` bytes, so
            # only those are ever scanned or kept between reads: the per-read
            # scan (a decoder per candidate format, each copying its input)
            # and the buffer stay bounded whatever the peer sends, instead of
            # growing with every byte an unauthenticated peer pushes.
            buffered = self._preNegotiationBuffer_incoming + data
            head, tail = buffered[:limit], buffered[limit:]
            try:
                [encoder, decoder] = self._negotiation_manager.doServerSideNegotiation(head)
            except NegotiationFailedException:
                if tail:
                    # More than a whole negotiation record has arrived and none
                    # of it decoded as one: nothing later can, so drop the lot
                    # and tell the caller to close.
                    raise NegotiationFailedException(
                        str(len(buffered)) + ' bytes arrived and none decoded '
                        'as a negotiation record')
                # A record may still be in flight; keep waiting for it.
                self._preNegotiationBuffer_incoming = head
                raise ChannelNotReadyException()
            except Exception as e:
                # The cell decoded but names a format this server cannot serve
                # (a mismatched definitions release). Waiting cannot fix that.
                raise NegotiationFailedException(str(e))
            self._encoder = encoder
            self._decoder = decoder
            # Bytes past the record are the start of the negotiated stream.
            decoder.push(tail)
            self._preNegotiationBuffer_incoming = b''
            self._negotiationComplete = True
            retval = b''

        return retval

    def _processSend(self):
        retval = b''
        if self._isClient and not self._negotiationComplete:
            [encoder, decoder] = self._negotiation_manager._init_encoders(
                self._outgoing_regex,
                self._outgoing_length,
                self._incoming_regex,
                self._incoming_length)
            self._encoder = encoder
            self._decoder = decoder
            negotiation_cell = self._negotiation_manager.makeClientNegotiationCell(
                self._outgoing_regex, self._outgoing_length,
                self._incoming_regex, self._incoming_length)
            retval = negotiation_cell
            self._negotiationComplete = True
        return retval


class _FTESocketWrapper(FTEHelper, object):

    def __init__(self, _socket,
                 outgoing_regex=None, outgoing_length=-1,
                 incoming_regex=None, incoming_length=-1,
                 K1=None, K2=None,
                 negotiate=True):

        self._socket = _socket
        self._outgoing_regex = outgoing_regex
        self._outgoing_length = outgoing_length
        self._incoming_regex = incoming_regex
        self._incoming_length = incoming_length
        self._K1 = K1
        self._K2 = K2
        self._negotiate = negotiate

        self._negotiation_manager = NegotiationManager(K1, K2)
        self._incoming_buffer = b''
        self._preNegotiationBuffer_outgoing = b''
        self._preNegotiationBuffer_incoming = b''
        # Set once the peer can never deliver another byte (negotiation refused
        # or a record failed authentication); recv then reports EOF and reads
        # nothing more from the socket.
        self._failed = False

        if negotiate:
            # Standard relay mode: client sends negotiation cell, server waits for it
            self._negotiationComplete = False
            self._isServer = (outgoing_regex is None and incoming_regex is None)
            self._isClient = (outgoing_regex is not None and incoming_regex is not None)
        else:
            # No negotiation: both sides know the formats, set up encoders immediately
            self._negotiationComplete = True
            self._isServer = False
            self._isClient = False
            [self._encoder, self._decoder] = self._negotiation_manager._init_encoders(
                outgoing_regex, outgoing_length,
                incoming_regex, incoming_length)

    def fileno(self):
        return self._socket.fileno()

    def setsockopt(self, level, optname, value):
        return self._socket.setsockopt(level, optname, value)

    def getsockopt(self, level, optname, buflen=None):
        if buflen is None:
            return self._socket.getsockopt(level, optname)
        return self._socket.getsockopt(level, optname, buflen)

    def _streamFailed(self):
        """Whether this connection can never deliver another byte: the peer
        failed to negotiate, or a record failed authentication after it."""
        return self._failed or (self._negotiationComplete and self._decoder.failed)

    def recv(self, bufsize):
        # <HACK>
        # Required to deal with case when client attempts to recv
        # before sending. This checks to ensure that a negotiate
        # cell is sent no matter what the client does first.
        to_send = self._processSend()
        if to_send:
            numbytes = self._socket.send(to_send)
            assert numbytes == len(to_send)
        # </HACK>

        if self._streamFailed():
            # Report EOF without reading: whatever the peer sends now can never
            # decode, and reading it would only buffer it.
            return b''

        try:
            while True:
                data = self._socket.recv(bufsize)
                noData = (data == b'')
                if noData and self._isServer and not self._negotiationComplete:
                    # The peer closed before a negotiation cell decoded. Nothing
                    # more will arrive, so report EOF. Treating this as "not
                    # ready yet" (a socket.timeout) made the relay worker poll
                    # the closed socket forever, since recv keeps returning b''.
                    if self._preNegotiationBuffer_incoming:
                        fteproxy.warn(
                            'peer closed before negotiation completed: check '
                            'that both endpoints share the key, '
                            '--record-layer-mode, and the same fteproxy/libfte '
                            'line (0.4 is not wire-compatible with 0.3)')
                    else:
                        fteproxy.info('peer closed without sending anything')
                    return b''
                data = self._processRecv(data)

                if noData and not self._incoming_buffer and not self._decoder._buffer:
                    return b''

                self._decoder.push(data)

                while True:
                    frag = self._decoder.pop()
                    if not frag:
                        break
                    self._incoming_buffer += frag

                if self._decoder.failed:
                    # Deliver whatever decoded before the bad record; the next
                    # recv reports EOF and the caller closes the connection.
                    fteproxy.warn(
                        'closing connection: a record failed authentication '
                        '(wrong key, corrupted or replayed stream, or a peer on '
                        'a different --record-layer-mode)')
                    break

                if self._incoming_buffer:
                    break

                if noData:
                    # The peer has closed the connection (recv returned b'').
                    # No further bytes will ever arrive, so any undecodable data
                    # still sitting in the decoder buffer (e.g. a covertext cell
                    # the peer was cut off part-way through) can never complete.
                    # Report EOF instead of busy-looping on the closed socket.
                    return b''

            retval = self._incoming_buffer
            self._incoming_buffer = b''
        except ChannelNotReadyException:
            raise socket.timeout
        except NegotiationFailedException as e:
            self._failed = True
            self._preNegotiationBuffer_incoming = b''
            fteproxy.warn(
                'closing connection: negotiation failed: ' + str(e) + ' (check '
                'that both endpoints share the key, --record-layer-mode, and '
                'the same fteproxy/libfte line; or the peer is not an fteproxy '
                'client)')
            return b''

        return retval
    
    def send(self, data):
        to_send = self._processSend()
        if to_send:
            self._socket.sendall(to_send)

        self._encoder.push(data)
        while True:
            to_send = self._encoder.pop()
            if not to_send:
                break
            self._socket.sendall(to_send)
        return len(data)

    def sendall(self, data):
        return self.send(data)

    def gettimeout(self):
        return self._socket.gettimeout()

    def settimeout(self, val):
        return self._socket.settimeout(val)

    def shutdown(self, flags):
        return self._socket.shutdown(flags)

    def close(self):
        return self._socket.close()

    def connect(self, addr):
        return self._socket.connect(addr)

    def accept(self):
        conn, addr = self._socket.accept()
        conn = _FTESocketWrapper(conn,
                                 self._outgoing_regex, self._outgoing_length,
                                 self._incoming_regex, self._incoming_length,
                                 self._K1, self._K2,
                                 self._negotiate)

        return conn, addr

    def bind(self, addr):
        return self._socket.bind(addr)

    def listen(self, N):
        return self._socket.listen(N)


def wrap_socket(sock,
                outgoing_regex=None, outgoing_length=-1,
                incoming_regex=None, incoming_length=-1,
                K1=None, K2=None,
                negotiate=True):
    """``fteproxy.wrap_socket`` turns an existing socket into an fteproxy socket.

    The input parameter ``sock`` is the socket to wrap.
    The parameter ``outgoing_regex`` specifies the format of the messages
    to send via the socket. The ``outgoing_length`` parameter is the exact
    length, in bytes, of every formatted covertext sent (libfte 0.4 emits
    fixed-length covertexts; the capacity of one covertext follows from the
    pattern and the length, and building the cipher raises
    ``fte.FormatCapacityError`` if the format cannot hold even an empty
    message at that length).
    The parameters ``incoming_regex`` and ``incoming_length`` are defined
    similarly.
    The optional parameters ``K1`` and ``K2`` specify 128-bit keys to be used
    in FTE's underlying AE scheme. If specified, these values must be 16-byte
    strings. If omitted, the key from ``fteproxy.conf`` is used, which is the
    public built-in default unless the application has set
    ``runtime.fteproxy.encrypter.key``; always share a secret key.

    The record-layer mode (``hybrid`` or ``format``) comes from
    ``runtime.fteproxy.record_layer.mode`` in ``fteproxy.conf`` and must be the
    same on both endpoints.

    The ``negotiate`` parameter controls whether the client sends a negotiation
    cell to establish the format. Set to ``False`` when both sides already know
    the formats (e.g., in symmetric client/server examples). Default is ``True``
    for backwards compatibility with the relay use case.
    """

    assert K1 == None or len(K1) == 16
    assert K2 == None or len(K2) == 16

    socket_wrapped = _FTESocketWrapper(
        sock,
        outgoing_regex, outgoing_length,
        incoming_regex, incoming_length,
        K1, K2,
        negotiate)
    return socket_wrapped
