#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__version__ = "1.0.0"

import os
import sys
import hmac
import collections
import functools
import logging
import re
import socket
import hashlib
import threading
import time

import fteproxy.conf
import fteproxy.defs
import fteproxy.handshake
import fteproxy.record_layer
import fteproxy.stream

import fte

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Re-exported: key generation belongs to the public API even though the
# implementation lives with the handshake it feeds.
from fteproxy.handshake import generate_server_key, server_id  # noqa: F401


@functools.lru_cache(maxsize=256)
def _regex_format(pattern, length):
    """The cached half of a libfte cipher: the compiled DFA.

    ``fte.RegexFormat`` compiles the pattern's DFA and builds its ranking
    tables, which is the expensive part of standing a cipher up and depends
    only on ``(pattern, length)``. libfte 0.3 cached this globally; 0.4 does
    not, and fteproxy builds a cipher per connection, so caching it here is
    what keeps connection setup at a few milliseconds.

    The tables are read-only, so one instance serves every connection and
    thread.
    """
    return fte.RegexFormat(pattern, length=length)


def _make_cipher(pattern, length, key):
    """A libfte 0.4 cipher that hides bytes as one fixed-length covertext.

    ``pattern`` is the regex whose language the covertext is drawn from;
    ``length`` picks the fixed covertext length; ``key`` is 32 bytes. The
    cipher ``encrypt``/``decrypt`` one whole covertext per call; the record
    layer handles stream chunking and framing on top of it.

    Deliberately not cached: since 1.0 every connection derives its own header
    keys, so a cache keyed on the key would grow by one entry per connection
    and never hit. ``fte.FTE`` holds only a reference to the (cached) format
    and the key schedule, and costs a couple of microseconds to build.
    """
    return fte.FTE(output_format=_regex_format(pattern, length), key=key)


@functools.lru_cache(maxsize=256)
def _cover_cipher(pattern, length, key):
    """The cipher for handshake records, cached.

    ``K_cover`` is derived from the server's long-term public key, so it is
    the same for every connection: unlike the session ciphers this one is
    worth caching, and the server's first-record scan tries several of them
    per connection.
    """
    return _make_cipher(pattern, length, key)


def _hybrid_mode():
    """Whether this end's *default* record-layer mode is 'hybrid'.

    'hybrid' (the default) formats only a fixed-length header per record and
    carries the body as raw authenticated bytes: much faster for bulk transfer,
    but everything past the header looks like random data. 'format' (opt-in)
    transforms every covertext byte into the target format for full-stream
    realism. See ``runtime.fteproxy.record_layer.mode`` in ``fteproxy.conf``.

    Since 1.0 the mode is not a setting both endpoints must match by hand: the
    client puts its choice in the handshake and the server follows. This is
    where the client's choice comes from when the caller does not pass one.
    """
    return fteproxy.conf.getValue('runtime.fteproxy.record_layer.mode') == 'hybrid'


class _AEADBody:
    """AES-128-CTR + HMAC-SHA256 (Encrypt-then-MAC) carrier for hybrid-mode bodies.

    Matches libfte's AE construction (the FTE paper's CTR+HMAC). Encrypt-then-MAC
    means a nonce collision costs only the confidentiality of the colliding
    pair, never authenticity. Each record binds its sequence number into the
    MAC, so a record reordered, dropped, or replayed within its stream fails
    authentication. Since 1.0 the key is per connection *and* per direction
    (``K_c2s_body`` / ``K_s2c_body`` from :mod:`fteproxy.handshake`), so a
    record replayed into another connection or the other direction fails too --
    the cross-stream replay gap SECURITY.md used to document. The encryption
    and MAC subkeys are derived from a distinct namespace, domain-separated
    from the header cipher's key. libfte does the same construction for the
    formatted header; this is the raw-body counterpart the FTE paper appended
    as unformatted ciphertext.
    """
    _NONCE = 12
    _TAG = 16
    _COUNTER = 16  # AES block: 12-byte nonce || 4-byte block counter
    # The record layer prepends a one-byte record type before sealing.
    _TYPE = 1
    # Largest payload a single record carries. Bounds memory and amortizes the
    # one formatted header per record over a large payload. The type byte is
    # not taken out of it: unlike a covertext, the body has no fixed width, so
    # a 1 MiB write still travels as exactly one record.
    max_plaintext_bytes = 2 ** 20
    # Largest framed body (nonce || ciphertext || tag) a header may announce;
    # the decoder refuses to buffer more than this for one record.
    max_framed_bytes = max_plaintext_bytes + _TYPE + _NONCE + _TAG

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


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

class RedactingFilter(logging.Filter):
    """Strips secrets out of every record logged through ``fteproxy``.

    A backstop, not a licence: no call site should format a key, a server-id
    or handshake material into a message in the first place. What this catches
    is the case nobody thought of -- an exception's ``str()``, a connection
    string echoed in an error, a hex key pasted into a debug line -- because a
    log file is the easiest place for a server-id to escape to.

    Installed on the package logger at import, so it applies to every handler,
    including one an embedding program attaches.
    """

    _PATTERNS = (
        # A connection string: keep the shape, drop the server-id.
        (re.compile(r'fte://[A-Za-z0-9_\-]+@'), 'fte://…@'),
        # 16 bytes or more of hex: a key, a MAC, or a transcript hash.
        (re.compile(r'(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])'),
         '<redacted>'),
        # A bare 43-character base64url token is a 32-byte public key.
        (re.compile(r'(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_\-])'),
         '<redacted>'),
    )

    def filter(self, record):
        message = record.getMessage()
        redacted = message
        for pattern, replacement in self._PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        if redacted != message:
            # Collapse to a plain string: the arguments are what carried the
            # secret, so they must not survive for a handler to re-expand.
            record.msg = redacted
            record.args = ()
        return True


logger = logging.getLogger('fteproxy')
"""The package logger. ``fteproxy.cli`` attaches a stderr handler to it and
sets its level from ``-q``/``-v``; embedding programs are free to attach their
own handlers instead. Nothing here configures the root logger, so importing
fteproxy never changes an application's logging setup.

Logging goes to stderr, never stdout, so a command whose output is data (for
example ``fteproxy formats``) stays pipeable.
"""
logger.addFilter(RedactingFilter())


def fatal_error(msg):
    """Log ``msg`` at ERROR and terminate with exit status 1.

    Reserved for conditions from which no connection can recover, such as a
    format provider that breaks libfte's ranking contract. Callers that can
    report a failure to their own caller should raise instead: this raises
    ``SystemExit``, which only unwinds the calling thread when it is not the
    main one.
    """
    logger.error(msg)
    sys.exit(1)


def warn(msg):
    """Log ``msg`` at WARNING: something is wrong but the process continues."""
    logger.warning(msg)


def info(msg):
    """Log ``msg`` at INFO: normal, low-volume progress reporting."""
    logger.info(msg)


def debug(msg):
    """Log ``msg`` at DEBUG: per-connection and per-record detail."""
    logger.debug(msg)


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #

class InvalidRoleException(Exception):
    """``wrap_socket`` was given neither, or both, of a server key and a
    server-id."""


class HandshakeFailedException(Exception):
    """This connection will never carry a session.

    On the server this is answered by silence: read and discard for a random
    interval, then close, so a prober cannot tell which check failed, or that
    anything was there to fail.
    """


class HandshakeTimeoutException(HandshakeFailedException):
    """No valid handshake reply arrived within the negotiate timeout."""


class ChannelNotReadyException(Exception):
    """The peer has not reached the point where this call can be served."""


class OpenRefused(Exception):
    """The peer would not open the requested stream.

    ``status`` is the SOCKS5 reply code it gave, so a SOCKS listener can pass
    it straight through to the application that asked.
    """

    def __init__(self, status, message=None):
        self.status = status
        super().__init__(message or ('open refused: %s'
                                     % fteproxy.stream.status_name(status)))


class _NeedMoreData(Exception):
    """Internal: the server has not yet buffered a whole client hello."""


class _PeerClosed(Exception):
    """Internal: the peer closed before the handshake could complete."""


# --------------------------------------------------------------------------- #
# Session set-up
# --------------------------------------------------------------------------- #

#: The base name of the request format that most recently matched a client
#: hello. The server's first-record scan tries it first, so a server whose
#: clients share a format pays one decrypt attempt per connection instead of
#: one per candidate format. Process-wide and advisory: a wrong guess only
#: costs the rest of the scan.
_last_matched_format = None

#: Client ephemeral keys seen inside the epoch window, shared by every
#: connection this process accepts.
_replay_filter = fteproxy.handshake.ReplayFilter()


def _format_pair(base):
    """``('base-request', 'base-response')``, validated against the
    definitions."""
    request, response = base + '-request', base + '-response'
    fteproxy.defs.getRegex(request)
    fteproxy.defs.getRegex(response)
    return request, response


def _cipher_for(format_name, key, cover=False):
    build = _cover_cipher if cover else _make_cipher
    return build(fteproxy.defs.getRegex(format_name),
                 fteproxy.defs.getLength(format_name), key)


def _session_channel(base, mode, keys, is_client):
    """Build the ``(Encoder, Decoder)`` pair for one end of a session.

    Each direction gets its own header key and body key, so the two directions
    are cryptographically independent streams that happen to share a socket.
    """
    request, response = _format_pair(base)
    outgoing, incoming = ((request, response) if is_client
                          else (response, request))
    out_header, out_body = keys.outgoing(is_client)
    in_header, in_body = keys.incoming(is_client)
    hybrid = (mode == fteproxy.handshake.MODE_HYBRID)
    encoder = fteproxy.record_layer.Encoder(
        cipher=_cipher_for(outgoing, out_header),
        body_cipher=_make_body_cipher(out_body) if hybrid else None)
    decoder = fteproxy.record_layer.Decoder(
        cipher=_cipher_for(incoming, in_header),
        body_cipher=_make_body_cipher(in_body) if hybrid else None)
    return encoder, decoder


def _request_scan_order():
    """Candidate request formats, most-recently-matched first."""
    definitions = fteproxy.defs.load_definitions()
    names = [name for name in definitions if name.endswith('-request')]
    preferred = _last_matched_format
    if preferred in names:
        return [preferred] + [name for name in names if name != preferred]
    return names


# --------------------------------------------------------------------------- #
# The socket wrapper
# --------------------------------------------------------------------------- #

class _FTESocketWrapper(object):
    """A socket whose bytes travel as a sequence of format-transformed records.

    One of two roles, decided by which key ``wrap_socket`` was given:

    client
        holds the server-id, opens with a client hello, and will not send an
        application byte until a server hello has proved the peer holds the
        matching private key.

    server
        holds the private key, learns the format and the mode from the first
        record, and answers a hello it cannot validate with silence rather
        than an error.

    Threading: one reader and one writer, as the relay uses it. The handshake
    lock serialises the two while it runs, since neither direction has keys
    until it finishes, and is released before any long read so a slow peer in
    one direction never blocks the other.
    """

    #: Never buffer more than this waiting for a client hello, or waiting for
    #: the handshake before the server can send. A hello is one covertext;
    #: anything beyond the largest format plus a margin is a peer that is not
    #: speaking this protocol.
    _MAX_PRE_HANDSHAKE_BYTES = 1 << 16

    def __init__(self, _socket, role, server_key=None, server_public=None,
                 format=None, mode=None, defs=None):
        self._socket = _socket
        self._role = role
        self._server_key = server_key
        self._server_public = server_public
        self._format = format
        self._mode = mode
        self._defs = defs
        self._cover_key = fteproxy.handshake.cover_key(server_public)

        self._handshake_lock = threading.RLock()
        self._send_lock = threading.RLock()
        self._handshake_done = False
        self._encoder = None
        self._decoder = None
        self._incoming_buffer = b''
        self._pre_handshake_incoming = b''
        self._pre_handshake_outgoing = b''
        self._control = collections.deque()
        self._peer_closed = False
        self._broken = False
        self._reject_deadline = None
        self._negotiated_format = None
        self._negotiated_mode = None

    # -- properties -------------------------------------------------------- #

    @property
    def negotiated_format(self):
        """The base format name in use, once the handshake has completed."""
        return self._negotiated_format

    @property
    def negotiated_mode(self):
        """``'hybrid'`` or ``'format'``, once the handshake has completed."""
        return self._negotiated_mode

    @property
    def handshake_complete(self):
        return self._handshake_done

    # -- handshake --------------------------------------------------------- #

    def handshake(self):
        """Complete the handshake now, blocking until it succeeds or fails.

        Idempotent. A client calls this straight after ``connect`` so that a
        bad connection string fails immediately rather than at the first byte.
        The server's relay calls it on a setup thread, so that a slow or
        hostile peer delays only its own connection and the accept loop never
        waits on one.

        Raises :class:`HandshakeFailedException` on a peer this end will not
        talk to (answer it with :meth:`reject_and_close`) and
        :class:`_PeerClosed` when the peer hung up first.
        """
        self._ensure_handshake()

    def _ensure_handshake(self):
        """Run the handshake if it has not run, and decode whatever arrived
        behind the client hello."""
        with self._handshake_lock:
            if self._handshake_done:
                return
            if self._role == 'client':
                self._client_handshake()
                return
            try:
                leftover = self._await_client_hello()
            except HandshakeFailedException as e:
                self._begin_reject(e)
                raise
            if leftover:
                self._decode(leftover)

    def _client_handshake(self):
        request, response = _format_pair(self._format)
        driver = fteproxy.handshake.ClientHandshake(
            server_public=self._server_public, format=self._format,
            mode=self._mode, defs=self._defs)
        request_cipher = _cipher_for(request, self._cover_key, cover=True)
        response_cipher = _cipher_for(response, self._cover_key, cover=True)

        sealed = fteproxy.record_layer._seal(request_cipher,
                                             driver.hello_bytes, 0)
        timeout = fteproxy.conf.getValue('runtime.fteproxy.handshake.timeout')
        try:
            self._socket.sendall(sealed)
            frame = self._read_exactly(
                response_cipher.output_format.max_length, timeout)
        except OSError as e:
            raise HandshakeFailedException('handshake I/O failed: %s' % e)
        if frame is None:
            raise HandshakeTimeoutException(
                'no valid handshake reply within %ss' % timeout)

        try:
            plaintext = response_cipher.decrypt(frame)
        except fte.FTEError:
            raise HandshakeFailedException(
                'the reply did not unseal as a %s covertext (wrong connection '
                'string, format, or definitions release)' % response)
        reply = fteproxy.record_layer._unseal(plaintext, 0)
        if reply is None:
            raise HandshakeFailedException('malformed server hello frame')
        try:
            keys = driver.finish(reply)
        except fteproxy.handshake.HandshakeError as e:
            raise HandshakeFailedException(str(e))

        self._negotiated_format = self._format
        self._negotiated_mode = self._mode
        self._encoder, self._decoder = _session_channel(
            self._format, self._mode, keys, is_client=True)
        self._handshake_done = True
        fteproxy.debug('handshake complete: protocol 1, %s, %s'
                       % (self._format, self._mode))
        self._flush_pre_handshake_outgoing()

    def _await_client_hello(self):
        """Block until a client hello decodes, or the handshake deadline passes.

        The server handshake is synchronous for the same reason the client's
        is: until it completes there is no format, no mode and no keys, so
        there is nothing useful to do with the socket. Bounding it also stops a
        peer that opens a connection, sends a few bytes and falls silent from
        holding a relay worker open indefinitely.
        """
        timeout = fteproxy.conf.getValue('runtime.fteproxy.handshake.timeout')
        deadline = time.monotonic() + timeout
        previous = self._socket.gettimeout()
        try:
            while True:
                try:
                    return self._server_handshake()
                except _NeedMoreData:
                    pass
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise HandshakeFailedException(
                        'no client hello within %ss' % timeout)
                self._socket.settimeout(remaining)
                try:
                    chunk = self._socket.recv(65536)
                except socket.timeout:
                    raise HandshakeFailedException(
                        'no client hello within %ss' % timeout)
                if not chunk:
                    raise _PeerClosed()
                self._pre_handshake_incoming += chunk
        finally:
            try:
                self._socket.settimeout(previous)
            except OSError:
                pass

    def _server_handshake(self):
        """Try to complete the handshake from ``_pre_handshake_incoming``.

        Tries each request format whose covertext could fit in what has
        arrived, most-recently-matched first, and asks libfte to unseal the
        leading covertext under ``K_cover``. A wrong guess is an
        ``InvalidCovertextError`` from the AE tag, so the scan simply falls
        through to the next candidate.

        Returns the bytes left over after the hello. Raises
        :class:`_NeedMoreData` while the hello could still be incomplete and
        :class:`HandshakeFailedException` once it cannot be one.
        """
        buffered = self._pre_handshake_incoming
        for name in _request_scan_order():
            length = fteproxy.defs.getLength(name)
            if len(buffered) < length:
                continue
            cipher = _cipher_for(name, self._cover_key, cover=True)
            try:
                plaintext = cipher.decrypt(buffered[:length])
            except fte.FTEError:
                continue
            hello_bytes = fteproxy.record_layer._unseal(plaintext, 0)
            if hello_bytes is None:
                continue
            return self._accept_hello(name, hello_bytes, buffered[length:])

        if len(buffered) > self._MAX_PRE_HANDSHAKE_BYTES:
            raise HandshakeFailedException(
                'no client hello in the first %d bytes' % len(buffered))
        raise _NeedMoreData()

    def _accept_hello(self, matched, hello_bytes, remainder):
        global _last_matched_format

        try:
            hello, reply_bytes, keys = fteproxy.handshake.accept_client_hello(
                hello_bytes, self._server_key, self._server_public,
                defs=self._defs, formats=fteproxy.defs.base_names(),
                replay=_replay_filter)
        except fteproxy.handshake.HandshakeError as e:
            raise HandshakeFailedException(str(e))

        # The covertext format and the name inside it are the same fact stated
        # twice, so they have to agree -- but by shape, not by name: two base
        # names in a definitions file may share a pattern and a length, and
        # then either one unseals the other's covertext. Comparing the names
        # would refuse a client that did nothing wrong.
        base = hello.format
        request, response = _format_pair(base)
        if (fteproxy.defs.getRegex(request), fteproxy.defs.getLength(request)) \
                != (fteproxy.defs.getRegex(matched),
                    fteproxy.defs.getLength(matched)):
            raise HandshakeFailedException('hello format does not match its '
                                           'covertext format')

        response_cipher = _cipher_for(response, self._cover_key, cover=True)
        try:
            self._socket.sendall(
                fteproxy.record_layer._seal(response_cipher, reply_bytes, 0))
        except OSError as e:
            raise HandshakeFailedException('failed to send server hello: %s' % e)

        self._negotiated_format = base
        self._negotiated_mode = hello.mode
        self._encoder, self._decoder = _session_channel(
            base, hello.mode, keys, is_client=False)
        self._handshake_done = True
        _last_matched_format = matched
        self._pre_handshake_incoming = b''
        fteproxy.debug('handshake complete: protocol 1, %s, %s'
                       % (base, hello.mode))
        self._flush_pre_handshake_outgoing()
        return remainder

    def _flush_pre_handshake_outgoing(self):
        pending, self._pre_handshake_outgoing = self._pre_handshake_outgoing, b''
        if pending:
            with self._send_lock:
                self._encoder.push(pending)
                out = self._encoder.pop()
                if out:
                    self._socket.sendall(out)

    def _read_exactly(self, count, timeout):
        """Read exactly ``count`` bytes within ``timeout`` seconds, or None.

        Used only for the client's single handshake reply, whose length is
        fixed by the response format.
        """
        deadline = time.monotonic() + timeout
        previous = self._socket.gettimeout()
        buffer = b''
        try:
            while len(buffer) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._socket.settimeout(remaining)
                try:
                    chunk = self._socket.recv(count - len(buffer))
                except socket.timeout:
                    return None
                if not chunk:
                    return None
                buffer += chunk
            return buffer
        finally:
            try:
                self._socket.settimeout(previous)
            except OSError:
                pass

    # -- rejection --------------------------------------------------------- #

    def _begin_reject(self, reason):
        """Answer a failed handshake the way obfs4 does: with nothing.

        No error, no close, no timing signal. The connection stays open,
        reading and discarding, for a random interval, so an active prober
        that guessed the connection string wrong learns only that something
        accepted a TCP connection.
        """
        self._reject_deadline = time.monotonic() + fteproxy.handshake.reject_delay()
        fteproxy.debug('rejecting handshake without reply: %s' % (reason,))

    def _discard_until_deadline(self):
        previous = self._socket.gettimeout()
        try:
            while True:
                remaining = self._reject_deadline - time.monotonic()
                if remaining <= 0:
                    return b''
                self._socket.settimeout(min(remaining, 0.5))
                try:
                    if self._socket.recv(65536) == b'':
                        return b''
                except socket.timeout:
                    continue
                except OSError:
                    return b''
        finally:
            try:
                self._socket.settimeout(previous)
            except OSError:
                pass

    # -- records ----------------------------------------------------------- #

    def _decode(self, data):
        """Decode ``data`` into the incoming buffer and the control queue.

        A record type this version does not define marks the connection
        broken: only a peer holding the session keys can produce one, so it is
        a version mismatch, and continuing would mean guessing at the meaning
        of the bytes that follow.
        """
        if self._broken:
            return
        try:
            self._decoder.push(data)
            records = self._decoder.pop_records()
        except fteproxy.record_layer.UnknownRecordType as e:
            fteproxy.warn('closing connection: %s' % e)
            self._broken = True
            return
        except fteproxy.record_layer.StreamFailedError:
            self._broken = True
            return
        if self._decoder.failed:
            fteproxy.warn('closing connection: a record failed authentication '
                          '(wrong key, a corrupted or replayed stream, or a '
                          'peer on a different record-layer mode)')
            self._broken = True
        for record_type, payload in records:
            if record_type == fteproxy.record_layer.DATA:
                self._incoming_buffer += payload
            elif record_type == fteproxy.record_layer.CLOSE:
                self._peer_closed = True
            elif record_type == fteproxy.record_layer.PADDING:
                continue
            else:
                self._control.append((record_type, payload))

    def _read_once(self, bufsize=65536):
        """Read once from the socket and decode. False at end of stream."""
        data = self._socket.recv(bufsize)
        self._decode(data)
        return bool(data) and not self._broken

    def send_record(self, record_type, payload=b''):
        """Send one control record. Requires a completed handshake."""
        self._ensure_handshake()
        if not self._handshake_done:
            raise ChannelNotReadyException(
                'cannot send a control record before the handshake')
        with self._send_lock:
            self._socket.sendall(self._encoder.encode(record_type, payload))

    def next_control_record(self):
        """Pop the next received control record, or None."""
        try:
            return self._control.popleft()
        except IndexError:
            return None

    def _take_control(self, record_type):
        """Pop the first queued record of ``record_type``, or None.

        Out-of-order control records stay queued rather than being dropped, so
        a peer that sends OPEN and OPEN_RESULT back to back does not lose one.
        """
        for index, (queued_type, payload) in enumerate(self._control):
            if queued_type == record_type:
                del self._control[index]
                return payload
        return None

    def _wait_control(self, record_type, timeout):
        """Block until a record of ``record_type`` arrives; return its payload.

        Returns None when the stream ends, or when application data arrives
        first -- which is how :meth:`wait_open` tells a relay client from a
        program using the library to send bytes with no OPEN at all.
        """
        self._ensure_handshake()
        deadline = None if timeout is None else time.monotonic() + timeout
        previous = self._socket.gettimeout()
        try:
            while True:
                payload = self._take_control(record_type)
                if payload is not None:
                    return payload
                if self._incoming_buffer or self._peer_closed or self._broken:
                    return None
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ChannelNotReadyException(
                            'no record of type 0x%02x within %ss'
                            % (record_type, timeout))
                    self._socket.settimeout(remaining)
                try:
                    if not self._read_once():
                        return None
                except socket.timeout:
                    raise ChannelNotReadyException(
                        'no record of type 0x%02x within %ss'
                        % (record_type, timeout))
        finally:
            try:
                self._socket.settimeout(previous)
            except OSError:
                pass

    # -- streams ----------------------------------------------------------- #

    def open(self, address, timeout=None):
        """Ask the peer to connect to ``address`` and wait for its answer.

        ``address`` is ``(host, port)``; the host may be a name, and the peer
        resolves it, so the client's DNS never leaves the tunnel. Raises
        :class:`OpenRefused` carrying the SOCKS5-style status on refusal.
        """
        host, port = address
        self.send_record(fteproxy.record_layer.OPEN,
                         fteproxy.stream.encode_open(host, port))
        payload = self._wait_control(fteproxy.record_layer.OPEN_RESULT, timeout)
        if payload is None:
            raise OpenRefused(fteproxy.stream.GENERAL_FAILURE,
                              'the peer closed without answering the OPEN')
        status = fteproxy.stream.decode_open_result(payload)
        if status != fteproxy.stream.SUCCEEDED:
            raise OpenRefused(status)
        return status

    def wait_open(self, timeout=None):
        """Wait for the peer's OPEN and return the ``(host, port)`` it names.

        Returns None when the peer sent application data first, which is what
        a program using the library as a plain encrypted socket does.
        """
        payload = self._wait_control(fteproxy.record_layer.OPEN, timeout)
        if payload is None:
            return None
        return fteproxy.stream.decode_open(payload)

    def open_result(self, status):
        """Answer an OPEN with a SOCKS5-style status byte."""
        self.send_record(fteproxy.record_layer.OPEN_RESULT,
                         fteproxy.stream.encode_open_result(status))

    def close_write(self):
        """Tell the peer this end will send no more application data.

        The record-layer half-close: the connection stays open in the other
        direction, which is what a plain socket's ``shutdown(SHUT_WR)`` means
        and what an HTTP client that finishes its request while waiting for a
        response relies on.
        """
        try:
            self.send_record(fteproxy.record_layer.CLOSE)
        except (ChannelNotReadyException, OSError) as e:
            fteproxy.debug('could not send CLOSE: %s' % e)

    @property
    def peer_closed(self):
        """Whether the peer has sent CLOSE: no more DATA will arrive."""
        return self._peer_closed

    def pending_eof(self):
        """Whether :meth:`recv` would return EOF without waiting for the socket.

        The peer's CLOSE can arrive in the same read as its last bytes, in
        which case nothing more will ever make the socket readable and a relay
        polling with ``select`` would wait for a wakeup that never comes.
        ``fteproxy.network_io`` asks this before selecting.
        """
        return ((self._peer_closed or self._broken)
                and not self._incoming_buffer)

    def reject_and_close(self):
        """Finish a connection whose handshake failed, then close it.

        Runs out the discard interval :meth:`_begin_reject` set, so a prober
        sees a connection that read its bytes and said nothing, and closes
        after the same delay whatever it got wrong.
        """
        try:
            if self._reject_deadline is not None:
                self._discard_until_deadline()
        finally:
            try:
                self._socket.close()
            except OSError:
                pass

    # -- socket interface -------------------------------------------------- #

    def fileno(self):
        return self._socket.fileno()

    def setsockopt(self, level, optname, value):
        return self._socket.setsockopt(level, optname, value)

    def getsockopt(self, level, optname, buflen=None):
        if buflen is None:
            return self._socket.getsockopt(level, optname)
        return self._socket.getsockopt(level, optname, buflen)

    def recv(self, bufsize):
        if self._reject_deadline is not None:
            return self._discard_until_deadline()
        try:
            self._ensure_handshake()
        except _PeerClosed:
            fteproxy.debug('peer closed before a client hello decoded'
                           if self._pre_handshake_incoming
                           else 'peer closed without sending anything')
            return b''
        except HandshakeFailedException:
            return self._discard_until_deadline()

        while True:
            if self._incoming_buffer:
                out, self._incoming_buffer = self._incoming_buffer, b''
                return out
            if self._peer_closed or self._broken:
                return b''
            # False here means end of stream: no further bytes will ever
            # arrive, so anything still in the decoder's buffer can never
            # complete. Report EOF rather than busy-looping on a dead socket.
            if not self._read_once(bufsize) and not self._incoming_buffer:
                return b''

    def send(self, data):
        with self._handshake_lock:
            if not self._handshake_done:
                if self._role == 'client':
                    self._client_handshake()
                else:
                    # The server has not seen a hello yet, so it knows neither
                    # the format nor the keys. Hold the bytes; a destination
                    # that speaks first (an SSH or SMTP banner) is this case.
                    if (len(self._pre_handshake_outgoing) + len(data)
                            > self._MAX_PRE_HANDSHAKE_BYTES):
                        raise ChannelNotReadyException(
                            'too much data buffered before the handshake')
                    self._pre_handshake_outgoing += data
                    return len(data)
        with self._send_lock:
            self._encoder.push(data)
            out = self._encoder.pop()
            if out:
                self._socket.sendall(out)
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
        self._socket.connect(addr)
        if self._role == 'client':
            self.handshake()

    def accept(self):
        conn, addr = self._socket.accept()
        return _FTESocketWrapper(conn, self._role,
                                 server_key=self._server_key,
                                 server_public=self._server_public,
                                 format=self._format, mode=self._mode,
                                 defs=self._defs), addr

    def bind(self, addr):
        return self._socket.bind(addr)

    def listen(self, N):
        return self._socket.listen(N)


def wrap_socket(sock, server_key=None, server_id=None,
                format=None, mode=None, defs=None):
    """Turn an existing socket into an fteproxy socket.

    Exactly one of ``server_key`` and ``server_id`` decides the role:

    ``server_key``
        the server's 32-byte X25519 private key, from
        :func:`fteproxy.generate_server_key`. The socket takes the server
        role: it learns the format, the mode and the definitions release from
        the client's first record, and answers anything it cannot validate
        with silence.

    ``server_id``
        the matching public key, as 32 bytes or 43 base64url characters. The
        socket takes the client role and opens with a hello. ``format`` (a
        base name such as ``manual-http``, default from ``fteproxy.conf``),
        ``mode`` (``hybrid`` or ``format``) and ``defs`` are the client's
        choices; the server follows them.

    Both ends derive their own header and body keys for each direction from
    the handshake, so nothing has to be configured to match and no two
    connections share a record key.
    """
    if (server_key is None) == (server_id is None):
        raise InvalidRoleException(
            'wrap_socket needs exactly one of server_key (server role) and '
            'server_id (client role)')

    if server_key is not None:
        role = 'server'
        server_key = _as_key_bytes(server_key, 'server_key')
        server_public = fteproxy.handshake.server_id(server_key)
    else:
        role = 'client'
        server_public = _as_key_bytes(server_id, 'server_id')

    if format is None:
        format = fteproxy.conf.getValue('fteproxy.default_format')
    if mode is None:
        mode = (fteproxy.handshake.MODE_HYBRID if _hybrid_mode()
                else fteproxy.handshake.MODE_FORMAT)
    if mode not in fteproxy.handshake.MODES:
        raise ValueError('mode must be one of %r' % (fteproxy.handshake.MODES,))
    if defs is None:
        defs = fteproxy.conf.getValue('fteproxy.defs.release')

    return _FTESocketWrapper(sock, role, server_key=server_key,
                             server_public=server_public, format=format,
                             mode=mode, defs=int(defs))


def _as_key_bytes(value, what):
    """Accept a key as raw bytes or as base64url without padding."""
    if isinstance(value, (bytes, bytearray)):
        if len(value) != fteproxy.handshake.KEY_BYTES:
            raise ValueError('%s must be %d bytes'
                             % (what, fteproxy.handshake.KEY_BYTES))
        return bytes(value)
    if isinstance(value, str):
        import base64
        padded = value + '=' * (-len(value) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded)
        except (ValueError, TypeError):
            raise ValueError('%s is not valid base64url' % what)
        if len(raw) != fteproxy.handshake.KEY_BYTES:
            raise ValueError('%s must decode to %d bytes'
                             % (what, fteproxy.handshake.KEY_BYTES))
        return raw
    raise TypeError('%s must be bytes or a base64url string' % what)
