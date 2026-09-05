#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__version__ = "1.0.0"

import os
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
import fteproxy.key_codec
import fteproxy.record_layer
import fteproxy.stream

import fte

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Re-exported: key generation belongs to the public API even though the
# implementation lives with the handshake it feeds.
from fteproxy.handshake import generate_server_key, server_id  # noqa: F401


@functools.lru_cache(maxsize=1024)
def _regex_format(pattern, length):
    """Cache ranking tables by (pattern, length) for reuse across sessions.

    The bounded cache contains no session keys. Variable formats use one entry
    per allowed length; evicted entries are recompiled when needed.
    """
    return fte.RegexFormat(pattern, length=length)


def _make_cipher(pattern, length, key):
    """Build a keyed libfte cipher over cached fixed-length ranking tables.

    key is 32 bytes. encrypt/decrypt handle one covertext; the record layer handles
    stream framing. Session ciphers are not cached because their keys are fresh.
    """
    return fte.FTE(output_format=_regex_format(pattern, length), key=key)


@functools.lru_cache(maxsize=1024)
def _cover_cipher(pattern, length, key):
    """Cache a handshake cipher keyed by the server's connection capability."""
    return _make_cipher(pattern, length, key)


def _hybrid_mode():
    """Return whether the configured socket-API mode default is hybrid.

    The CLI applies URI and per-format hints separately.
    """
    return fteproxy.conf.getValue('runtime.fteproxy.record_layer.mode') == 'hybrid'


class _AEADBody:
    """Authenticate hybrid bodies with AES-128-CTR and truncated HMAC-SHA256.

    Encryption and MAC subkeys have separate derivation labels. The MAC binds the
    sequence number, nonce, and ciphertext. Session setup provides distinct body
    keys for each direction; see SECURITY.md for the security model.
    """
    _NONCE = 12
    _TAG = 16
    _COUNTER = 16  # AES block: 12-byte nonce || 4-byte block counter
    # The record layer prepends a one-byte record type before sealing.
    _TYPE = 1
    # Maximum hybrid payload, excluding the type byte. A 1 MiB payload fits one record.
    max_plaintext_bytes = 2 ** 20
    # Maximum body length accepted from an authenticated hybrid header.
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
    """Redact recognized URI credentials, hex keys, and base64url key tokens.

    Installed on the package logger. This is a pattern-based backstop; callers
    must still avoid logging secrets or handshake material.
    """

    _PATTERNS = (
        # A connection string: keep the shape, drop the server-id.
        # Redact the whole authority token even when it is malformed. Strict
        # parsing rejects junk, but a parse error or debug message must not
        # become a way to log the secret-bearing input.
        (re.compile(r'fte://[^@\s]+@'), 'fte://…@'),
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
# The CLI installs a stderr handler; embedding applications may add their own.
# Importing this module leaves the root logger unchanged.
logger.addFilter(RedactingFilter())


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
    """The peer did not complete an acceptable handshake.

    The server driver responds with silence and a delayed close; clients receive
    the exception directly.
    """


class HandshakeTimeoutException(HandshakeFailedException):
    """No valid server hello arrived within the handshake timeout."""


class ChannelNotReadyException(Exception):
    """The peer has not reached the point where this call can be served."""


class HybridUnsupportedError(Exception):
    """This format cannot run in ``hybrid`` mode.

    Raised when no covertext length the format emits has room for a hybrid
    header (:data:`fteproxy.record_layer.HYBRID_HEADER_BYTES`). Refusing is the
    point: falling back to another length would leave the two ends framing the
    stream differently, which surfaces as a connection that authenticates its
    handshake and then cannot decode a record. ``--mode format`` runs such a
    format; no shipped format is one.
    """


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

# Most recently matched request base, tried first during the next server scan.
# Advisory and process-wide; a wrong guess falls through to other candidates.
_last_matched_format = None

#: Client ephemeral keys seen inside the epoch window, shared by every
#: connection this process accepts.
_replay_filter = fteproxy.handshake.ReplayFilter()


def _format_pair(base, definitions=None):
    """``('base-request', 'base-response')``, validated against the
    definitions."""
    request, response = base + '-request', base + '-response'
    fteproxy.defs.getRegex(request, definitions)
    fteproxy.defs.getRegex(response, definitions)
    return request, response


def _message_length(framing, length):
    """The covertext length a cipher is built at, given a length on the wire.

    The two differ only for ``length-prefix`` framing, where
    :data:`fteproxy.defs.LENGTH_PREFIX_BYTES` of the wire record are the framing
    header rather than covertext. Callers that only want the DFA (the startup
    warm-up in :func:`fteproxy.cli.check_format`) use this; callers that want a
    cipher use :func:`_framed_cipher`, which applies it for them.
    """
    if framing == fteproxy.defs.FRAMING_LENGTH_PREFIX:
        return length - fteproxy.defs.LENGTH_PREFIX_BYTES
    return length


def _framed_cipher(regex, length, key, framing, build=None):
    """Build a cipher for a wire length, including any external prefix.

    For length-prefix framing, build at length - 2 and wrap with LengthPrefixed.
    build optionally selects the cached handshake-cipher factory.
    """
    build = _make_cipher if build is None else build
    cipher = build(regex, _message_length(framing, length), key)
    if framing == fteproxy.defs.FRAMING_LENGTH_PREFIX:
        return fteproxy.record_layer.LengthPrefixed(cipher)
    return cipher


def _spec_cipher(spec, length, key, build=None):
    """:func:`_framed_cipher` for a definitions entry at one of its wire lengths."""
    return _framed_cipher(spec['regex'], length, key,
                          fteproxy.defs.spec_framing(spec), build=build)


def _cipher_for(format_name, key, cover=False, definitions=None):
    spec = fteproxy.defs._spec(format_name, definitions)
    build = _cover_cipher if cover else _make_cipher
    return _spec_cipher(spec, fteproxy.defs.spec_length(spec), key, build=build)


# --------------------------------------------------------------------------- #
# The hybrid header length
# --------------------------------------------------------------------------- #

# Probe key for capacity measurements; capacity depends on format and length,
# not on key material, so both peers derive the same header length.
_PROBE_KEY = b'\x00' * 32


@functools.lru_cache(maxsize=1024)
def _hybrid_header_length(regex, framing, lengths):
    """Return the shortest candidate length with room for a sealed header.

    Probe real cipher capacities and cache by regex, framing, and length set.
    Skip unbuildable candidates; full format validation reports those separately.
    """
    for length in lengths:
        try:
            capacity = _framed_cipher(regex, length, _PROBE_KEY,
                                      framing).max_plaintext_bytes
        except (fte.FTEError, ValueError):
            continue
        if capacity >= fteproxy.record_layer.HYBRID_HEADER_BYTES:
            return length
    return None


def hybrid_header_length(spec):
    """Return the shortest allowed wire length that holds a hybrid header.

    Use the hybrid regex and include external framing. The cipher needs 16 bytes
    of plaintext capacity: a 12-byte seal and four-byte body length. Return None
    if no candidate fits. Both peers derive this length from matching definitions.
    """
    return _hybrid_header_length(
        fteproxy.defs.spec_hybrid_regex(spec),
        fteproxy.defs.spec_framing(spec),
        tuple(fteproxy.defs.spec_allowed_lengths(spec)))


def _hybrid_header_cipher(format_name, key, definitions=None):
    """Build one direction's hybrid-header cipher or raise HybridUnsupportedError."""
    spec = fteproxy.defs._spec(format_name, definitions)
    length = hybrid_header_length(spec)
    if length is None:
        raise HybridUnsupportedError(
            'format %s has no covertext length that can hold a %d-byte hybrid '
            'header (it emits %r), so it cannot run in hybrid mode'
            % (format_name, fteproxy.record_layer.HYBRID_HEADER_BYTES,
               fteproxy.defs.spec_allowed_lengths(spec)))
    return _framed_cipher(fteproxy.defs.spec_hybrid_regex(spec), length, key,
                          fteproxy.defs.spec_framing(spec))


def _check_hybrid_supported(base, mode, definitions=None):
    """Require a capable hybrid-header length in both directions when hybrid is selected.

    The base-regex capacity floor alone does not validate a separate hybrid regex.
    """
    if mode != fteproxy.handshake.MODE_HYBRID:
        return
    for name in _format_pair(base, definitions):
        if hybrid_header_length(fteproxy.defs._spec(name, definitions)) is None:
            raise HybridUnsupportedError(
                'format %s has no covertext length that can hold a %d-byte '
                'hybrid header, so %s cannot run in hybrid mode; use '
                '"--mode format"'
                % (name, fteproxy.record_layer.HYBRID_HEADER_BYTES, base))


def _variable_lengths_for_spec(spec, key):
    """Build per-length session ciphers over cached ranking tables."""
    ciphers = {length: _spec_cipher(spec, length, key)
               for length in fteproxy.defs.spec_allowed_lengths(spec)}
    return fteproxy.record_layer.VariableLength(
        ciphers, fteproxy.defs.spec_terminator(spec),
        framing=fteproxy.defs.spec_framing(spec))


def _variable_for(format_name, key, definitions=None):
    """Return a format's VariableLength configuration, or None if fixed."""
    spec = fteproxy.defs._spec(format_name, definitions)
    if not fteproxy.defs.spec_is_variable(spec):
        return None
    return _variable_lengths_for_spec(spec, key)


def _session_channel(base, mode, keys, is_client, definitions=None):
    """Build one endpoint's (Encoder, Decoder) using per-direction session keys.

    Format mode builds all allowed lengths. Hybrid mode uses one header length
    per direction and applies the definition's body framing.
    """
    request, response = _format_pair(base, definitions)
    outgoing, incoming = ((request, response) if is_client
                          else (response, request))
    out_header, out_body = keys.outgoing(is_client)
    in_header, in_body = keys.incoming(is_client)
    hybrid = (mode == fteproxy.handshake.MODE_HYBRID)
    def header_cipher(name, key):
        if hybrid:
            return _hybrid_header_cipher(name, key, definitions)
        return _cipher_for(name, key, definitions=definitions)

    encoder = fteproxy.record_layer.Encoder(
        cipher=header_cipher(outgoing, out_header),
        body_cipher=_make_body_cipher(out_body) if hybrid else None,
        variable=None if hybrid else _variable_for(
            outgoing, out_header, definitions),
        hybrid_framing=(fteproxy.defs.spec_hybrid_framing(
            fteproxy.defs._spec(outgoing, definitions)) if hybrid
            else fteproxy.defs.HYBRID_FRAMING_RAW))
    decoder = fteproxy.record_layer.Decoder(
        cipher=header_cipher(incoming, in_header),
        body_cipher=_make_body_cipher(in_body) if hybrid else None,
        variable=None if hybrid else _variable_for(
            incoming, in_header, definitions),
        hybrid_framing=(fteproxy.defs.spec_hybrid_framing(
            fteproxy.defs._spec(incoming, definitions)) if hybrid
            else fteproxy.defs.HYBRID_FRAMING_RAW))
    return encoder, decoder


def _request_scan_order(definitions=None):
    """Candidate request formats, most-recently-matched first."""
    definitions = fteproxy.defs._catalog(definitions)
    names = [name for name in definitions if name.endswith('-request')]
    preferred = _last_matched_format
    if preferred in names:
        return [preferred] + [name for name in names if name != preferred]
    return names


# --------------------------------------------------------------------------- #
# The socket wrapper
# --------------------------------------------------------------------------- #

class _FTESocketWrapper(object):
    """A TCP socket carrying authenticated, format-transformed records.

    The client supplies the server identity and selects format/mode; the server
    supplies the private key and accepts those choices from its configured release.
    Support one reader and one writer. Handshake operations are serialized; normal
    reads release the handshake lock before waiting for application data.
    """

    # Pre-handshake send-queue limit and receive-buffer rejection threshold.
    # The receive check happens after a read, so that buffer can briefly exceed it.
    _MAX_PRE_HANDSHAKE_BYTES = 1 << 16

    # Maximum unread control records. Unconsumed OPEN traffic must not grow
    # per-connection memory indefinitely.
    _MAX_CONTROL_RECORDS = 16
    # Largest OPEN: address type + name length + 255-byte name + two-byte port.
    # Also bound bytes, since a hybrid body can be much larger than an OPEN.
    _MAX_CONTROL_BYTES = 512

    def __init__(self, _socket, role, server_key=None, server_public=None,
                 format=None, mode=None, defs=None):
        self._socket = _socket
        # Monotonic origin for the rejection deadline, independent of when a check fails.
        self._accepted_at = time.monotonic()
        self._role = role
        self._server_key = server_key
        self._server_public = server_public
        self._format = format
        self._mode = mode
        self._defs = int(defs)
        # A connection keeps one release-scoped catalog.  Every format and
        # cipher lookup below uses this mapping instead of whichever release a
        # different caller most recently selected in process-global config.
        self._definitions = fteproxy.defs.load_definitions(self._defs)
        self._cover_key = fteproxy.handshake.cover_key(server_public)

        self._handshake_lock = threading.RLock()
        self._send_lock = threading.RLock()
        self._handshake_done = False
        self._encoder = None
        self._decoder = None
        self._incoming_buffer = b''
        self._pre_handshake_incoming = b''
        self._pre_handshake_outgoing = b''
        #: Request formats whose covertext this connection's first bytes have
        #: already failed to unseal; see :meth:`_server_handshake`.
        self._failed_formats = set()
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
        """Complete the handshake once, blocking until success or failure.

        Client connect() calls this automatically. For an already-connected raw socket,
        call it explicitly or let the first I/O trigger it. A server setup worker calls
        it before starting the relay. Raises HandshakeFailedException or _PeerClosed.
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
        request, response = _format_pair(self._format, self._definitions)
        # Before a byte goes out: a mode this format cannot carry is this end's
        # own configuration error, and it should read as one rather than as a
        # server that would not answer.
        _check_hybrid_supported(
            self._format, self._mode, self._definitions)
        driver = fteproxy.handshake.ClientHandshake(
            server_public=self._server_public, format=self._format,
            mode=self._mode, defs=self._defs)
        request_cipher = _cipher_for(
            request, self._cover_key, cover=True,
            definitions=self._definitions)
        response_cipher = _cipher_for(
            response, self._cover_key, cover=True,
            definitions=self._definitions)

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
            self._format, self._mode, keys, is_client=True,
            definitions=self._definitions)
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
        """Try eligible request formats against the buffered client hello.

        Each candidate is tried at most once, after enough bytes arrive, with the most
        recently matched format first. Return bytes after the accepted hello.
        Raise _NeedMoreData while waiting or HandshakeFailedException on rejection.
        """
        buffered = self._pre_handshake_incoming
        for name in _request_scan_order(self._definitions):
            if name in self._failed_formats:
                continue
            length = fteproxy.defs.getLength(name, self._definitions)
            if len(buffered) < length:
                continue
            cipher = _cipher_for(
                name, self._cover_key, cover=True,
                definitions=self._definitions)
            try:
                plaintext = cipher.decrypt(buffered[:length])
            except fte.FTEError:
                self._failed_formats.add(name)
                continue
            hello_bytes = fteproxy.record_layer._unseal(plaintext, 0)
            if hello_bytes is None:
                self._failed_formats.add(name)
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
                defs=self._defs,
                formats=fteproxy.defs.base_names(self._definitions),
                replay=_replay_filter)
        except fteproxy.handshake.HandshakeError as e:
            raise HandshakeFailedException(str(e))

        # The covertext format and the name inside it are the same fact stated
        # twice, so they have to agree -- but by shape, not by name: two base
        # names in a definitions file may share a pattern and a length, and
        # then either one unseals the other's covertext. Comparing the names
        # would refuse a client that did nothing wrong.
        base = hello.format
        request, response = _format_pair(base, self._definitions)
        if (fteproxy.defs.getRegex(request, self._definitions),
                fteproxy.defs.getLength(request, self._definitions)) \
                != (fteproxy.defs.getRegex(matched, self._definitions),
                    fteproxy.defs.getLength(matched, self._definitions)):
            raise HandshakeFailedException('hello format does not match its '
                                           'covertext format')

        # Check hybrid support before replying to the client hello.
        try:
            _check_hybrid_supported(base, hello.mode, self._definitions)
        except HybridUnsupportedError as e:
            raise HandshakeFailedException(str(e))

        response_cipher = _cipher_for(
            response, self._cover_key, cover=True,
            definitions=self._definitions)
        try:
            self._socket.sendall(
                fteproxy.record_layer._seal(response_cipher, reply_bytes, 0))
        except OSError as e:
            raise HandshakeFailedException('failed to send server hello: %s' % e)

        self._negotiated_format = base
        self._negotiated_mode = hello.mode
        self._encoder, self._decoder = _session_channel(
            base, hello.mode, keys, is_client=False,
            definitions=self._definitions)
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
        """Set a no-reply rejection deadline relative to socket wrapping time.

        Include the handshake timeout and random delay so early and late validation
        failures use the same target lifetime. Peer closure, I/O errors, shutdown, and
        scheduling can alter the observed timing.
        """
        timeout = fteproxy.conf.getValue('runtime.fteproxy.handshake.timeout')
        self._reject_deadline = (self._accepted_at + timeout
                                 + fteproxy.handshake.reject_delay())
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
        """Decode DATA into the read buffer and queue OPEN/OPEN_RESULT records.

        Unknown types, decoder failure, or excessive control payloads/counts mark the
        connection broken. PADDING is ignored; CLOSE records logical EOF.
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
            elif len(payload) > self._MAX_CONTROL_BYTES:
                fteproxy.warn('closing connection: a %d-byte control record '
                              'exceeds the %d-byte limit'
                              % (len(payload), self._MAX_CONTROL_BYTES))
                self._broken = True
                self._control.clear()
                return
            elif len(self._control) >= self._MAX_CONTROL_RECORDS:
                # Dropping the record silently would leave the peer waiting
                # for an answer that is never coming, so the connection ends
                # instead: recv() reports EOF and the relay closes it.
                fteproxy.warn('closing connection: the peer queued more than '
                              '%d unread control records'
                              % self._MAX_CONTROL_RECORDS)
                self._broken = True
                self._control.clear()
                return
            else:
                self._control.append((record_type, payload))

    def _read_once(self, bufsize=65536):
        """Read once from the socket and decode. False at end of stream."""
        data = self._socket.recv(bufsize)
        self._decode(data)
        return bool(data) and not self._broken

    def send_record(self, record_type, payload=b''):
        """Complete the handshake if needed, then send one typed record."""
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
        """Request a destination and wait for its OPEN_RESULT.

        address is (host, port). Names are sent for the peer to resolve.
        Raise OpenRefused with a SOCKS5-style status on refusal, or
        ChannelNotReadyException if waiting for the result times out.
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
        """Return the requested (host, port), or None for DATA-first or ended streams.

        Raise ChannelNotReadyException on timeout or InvalidAddress for malformed OPEN.
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
        """Send CLOSE to signal logical EOF while keeping the read direction open.

        Callers must stop sending DATA afterward; this method does not enforce that.
        """
        try:
            self.send_record(fteproxy.record_layer.CLOSE)
        except (ChannelNotReadyException, OSError) as e:
            fteproxy.debug('could not send CLOSE: %s' % e)

    @property
    def peer_closed(self):
        """Whether a CLOSE record has been received."""
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

    def pending_read(self):
        """Whether :meth:`recv` can return without reading the raw socket.

        A control-record waiter can decode application DATA from the same raw
        read as its answer and leave that DATA in ``_incoming_buffer``. Code
        polling the wrapper must consult this logical readiness rather than
        relying exclusively on the underlying descriptor.
        """
        return bool(self._incoming_buffer) or self.pending_eof()

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
        """Return decoded application bytes, or b'' for an ended or broken stream.

        bufsize controls raw reads, not the maximum decoded return length. Applications
        must frame messages themselves; one send need not correspond to one recv.
        Server handshake rejection waits silently before EOF. Client handshake failures
        raise HandshakeFailedException.
        """
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
            if self._reject_deadline is None:
                # The client role never calls _begin_reject, so there is no
                # deadline to discard until. Report the failure rather than
                # tripping over a None.
                raise
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
    """Wrap a TCP socket in the client or server role.

    Pass exactly one of server_key (private identity) and server_id (public
    connection capability), as 32 raw bytes or canonical base64url text.
    The client selects format and mode; both peers must select matching defs.
    Defaults come from fteproxy.conf, without the CLI's port or mode-hint logic.

    Client connect() completes the handshake. For an already-connected socket,
    handshake() or first I/O completes it. Server accept() returns another wrapper.
    The API supports one reader and one writer, but is not a complete socket drop-in:
    recv(bufsize) may return more decoded bytes than bufsize, and sendall returns a
    byte count. Use close_write() for protocol half-close; shutdown() delegates to
    the raw socket. OPEN requests are separate from direct DATA exchange.
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
        try:
            return fteproxy.key_codec.decode_server_id(value)
        except ValueError as exc:
            raise ValueError('%s is not valid canonical base64url: %s'
                             % (what, exc)) from exc
    raise TypeError('%s must be bytes or a base64url string' % what)


# Keep the package root as the documented public facade. Imported last because
# ``fteproxy.config`` uses package logging helpers while it is being defined.
from fteproxy.config import ConnectionString  # noqa: E402,F401
