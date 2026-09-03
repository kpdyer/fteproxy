#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Protocol version 1: the fteproxy handshake and its key schedule.

Two records, one in each direction, both libfte covertexts sealed under a key
that anyone holding the connection string can compute:

===============  =========================================================
client -> server  version, flags, definitions release, format base name,
                  client ephemeral public key, epoch
server -> client  version, flags, server ephemeral public key, MAC
===============  =========================================================

This is the Noise ``NK`` message pattern (``e, es`` then ``e, ee``) written
out with ``cryptography``'s X25519, HKDF and HMAC. It authenticates the
server, gives forward secrecy, and derives a distinct header key and body key
for each direction, so no two connections and no two directions ever share a
record key. It does not authenticate the client beyond possession of the
connection string, which is the property obfs4 has.

What the connection string authorises
-------------------------------------
``K_cover`` is derived from the server's *public* key, so every holder of the
connection string can seal and unseal handshake records. That is deliberate:
holding the string is what authorises a connection attempt, and a prober that
does not hold it gets no reply at all. It does not let the holder impersonate
the server (the server hello's MAC requires the server's private key) nor read
another client's session (the session keys come from two ephemeral keys).

Nothing in this module does I/O or logging: it encodes, decodes, and derives.
:mod:`fteproxy` drives it over a socket, and the reject path -- read and
discard, never reply -- lives there.
"""

import functools
import hashlib
import hmac
import os
import struct
import threading
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand


PROTOCOL_VERSION = 1

MODE_HYBRID = 'hybrid'
MODE_FORMAT = 'format'
MODES = (MODE_HYBRID, MODE_FORMAT)

#: ``flags`` bit 0: 0 selects hybrid framing, 1 selects format framing.
FLAG_FORMAT_MODE = 0x01
#: Every other ``flags`` bit is reserved and must be zero. A future version
#: that assigns one negotiates its use through ``version``, so a v1 peer is
#: right to refuse a hello that sets one.
FLAG_RESERVED_MASK = 0xFE

KEY_BYTES = 32
MAC_BYTES = 16

#: The epoch counts hours, so a client and server whose clocks differ by less
#: than an hour usually agree, and ``EPOCH_WINDOW`` covers the rest.
EPOCH_SECONDS = 3600
EPOCH_WINDOW = 1

#: A ``c_pub`` is remembered for the whole accepted window. Past this many
#: entries the fullest hour starts forgetting; see :class:`ReplayFilter`.
REPLAY_MAX_ENTRIES = 1 << 17

_HASH_PREFIX = b'fteproxy/v1'
_COVER_INFO = b'fteproxy/v1/cover'
_KEYS_INFO = b'fteproxy/v1/keys'
#: K_auth_s, K_c2s_hdr, K_c2s_body, K_s2c_hdr, K_s2c_body.
_KEY_SCHEDULE_BYTES = 5 * KEY_BYTES

_ZERO_SHARED_SECRET = b'\x00' * KEY_BYTES

_CLIENT_HELLO_HEAD = struct.Struct('>BBIB')   # version, flags, defs, name len
_EPOCH = struct.Struct('>I')
_SERVER_HELLO_HEAD = struct.Struct('>BB')     # version, flags


class HandshakeError(Exception):
    """A handshake that cannot continue.

    The server answers every one of these the same way -- read and discard for
    a random interval, then close, without replying -- so that a prober learns
    nothing from which check failed. Instances carry a reason for the DEBUG
    log, never any key material.
    """


class InvalidHello(HandshakeError):
    """A hello that is malformed, of an unknown version, or out of policy."""


class ReplayedHello(InvalidHello):
    """A client ephemeral public key already seen inside the epoch window."""


# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #

def _hmac_sha256(key, data):
    mac = HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def _hkdf_extract(salt, ikm):
    """HKDF-Extract, which is exactly HMAC-SHA256 with the salt as the key."""
    return _hmac_sha256(salt, ikm)


def _hkdf_expand(prk, info, length):
    return HKDFExpand(algorithm=hashes.SHA256(), length=length,
                      info=info).derive(prk)


@functools.lru_cache(maxsize=8)
def _static_private_key(private_bytes):
    """The key object for a long-term private key, built once.

    Turning 32 bytes into an OpenSSL key object costs about as much as the
    scalar multiplication it is then used for, and a server drives every
    connection from the same static key. The bytes are already resident -- the
    process loaded them at startup and keeps them for its lifetime -- so the
    cache holds nothing that was not already in memory, and it is small
    because a process has one identity, not thousands. Ephemeral keys are
    never cached: they are used once, by the object that generated them.
    """
    return X25519PrivateKey.from_private_bytes(private_bytes)


def _x25519(private, peer_public_bytes):
    """One X25519 exchange, refusing a degenerate result.

    ``private`` is either an ``X25519PrivateKey`` (an ephemeral, held by the
    handshake that generated it) or its raw bytes.

    A peer public key of small order drives the shared secret to all zeroes,
    which would let anyone who can rewrite the hellos fix both sides' key
    schedule. ``cryptography`` already rejects most such points; the explicit
    check makes the guarantee ours and independent of the backend.
    """
    try:
        if not isinstance(private, X25519PrivateKey):
            private = _static_private_key(bytes(private))
        public = X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared = private.exchange(public)
    except ValueError as e:
        raise InvalidHello('X25519 exchange failed: %s' % e)
    if hmac.compare_digest(shared, _ZERO_SHARED_SECRET):
        raise InvalidHello('degenerate X25519 shared secret')
    return shared


def generate_server_key():
    """Return ``(private_bytes, public_bytes)`` for a new server identity.

    The public half is the server-id that goes in the connection string; the
    private half belongs in ``server.key`` with mode 0600 and nowhere else.
    """
    private = X25519PrivateKey.generate()
    return (private.private_bytes_raw(),
            private.public_key().public_bytes_raw())


def server_id(private_bytes):
    """The public server-id matching a 32-byte private key."""
    _check_key_length(private_bytes, 'server private key')
    return _static_private_key(
        bytes(private_bytes)).public_key().public_bytes_raw()


def cover_key(server_public):
    """``K_cover``: the key both handshake records are sealed under.

    Derived from the server's public key alone, so it is exactly as secret as
    the connection string.
    """
    _check_key_length(server_public, 'server public key')
    return HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=b'',
                info=_COVER_INFO).derive(server_public)


def _check_key_length(value, what):
    if not isinstance(value, (bytes, bytearray)) or len(value) != KEY_BYTES:
        raise ValueError('%s must be %d bytes' % (what, KEY_BYTES))


def current_epoch(now=None):
    """Hours since the Unix epoch, the units of the hello's ``epoch`` field."""
    return int((time.time() if now is None else now) // EPOCH_SECONDS)


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #

class ClientHello:
    """The client's half of the handshake, before sealing.

    ``version | flags | defs | format length | format | c_pub | epoch``
    """

    __slots__ = ('version', 'mode', 'defs', 'format', 'client_public', 'epoch')

    def __init__(self, mode, defs, format, client_public, epoch,
                 version=PROTOCOL_VERSION):
        self.version = version
        self.mode = mode
        self.defs = defs
        self.format = format
        self.client_public = client_public
        self.epoch = epoch

    def encode(self):
        if self.mode not in MODES:
            raise ValueError('unknown record-layer mode: %r' % (self.mode,))
        name = self.format.encode('ascii')
        if not 0 < len(name) <= 0xFF:
            raise ValueError('format name must be 1 to 255 ASCII characters')
        _check_key_length(self.client_public, 'client ephemeral public key')
        flags = FLAG_FORMAT_MODE if self.mode == MODE_FORMAT else 0
        return (_CLIENT_HELLO_HEAD.pack(self.version, flags, self.defs,
                                        len(name))
                + name + bytes(self.client_public) + _EPOCH.pack(self.epoch))

    @classmethod
    def decode(cls, data):
        """Parse a client hello, raising :class:`InvalidHello` on anything
        that is not exactly one well-formed v1 hello."""
        head = _CLIENT_HELLO_HEAD.size
        if len(data) < head:
            raise InvalidHello('client hello is %d bytes, too short'
                               % len(data))
        version, flags, defs, name_len = _CLIENT_HELLO_HEAD.unpack_from(data)
        if version != PROTOCOL_VERSION:
            raise InvalidHello('unsupported protocol version %d' % version)
        if flags & FLAG_RESERVED_MASK:
            raise InvalidHello('reserved flag bits set')
        expected = head + name_len + KEY_BYTES + _EPOCH.size
        if len(data) != expected:
            raise InvalidHello('client hello is %d bytes, expected %d'
                               % (len(data), expected))
        if name_len == 0:
            raise InvalidHello('empty format name')
        name = data[head:head + name_len]
        try:
            format_name = name.decode('ascii')
        except UnicodeDecodeError:
            raise InvalidHello('format name is not ASCII')
        offset = head + name_len
        client_public = data[offset:offset + KEY_BYTES]
        epoch = _EPOCH.unpack_from(data, offset + KEY_BYTES)[0]
        mode = MODE_FORMAT if flags & FLAG_FORMAT_MODE else MODE_HYBRID
        return cls(mode=mode, defs=defs, format=format_name,
                   client_public=client_public, epoch=epoch, version=version)


class ServerHello:
    """The server's reply, before sealing: ``version | flags | s_pub | mac``.

    ``mac`` is ``HMAC-SHA256(K_auth_s, H)[:16]``, and ``K_auth_s`` depends on
    ``DH_es``, so producing it proves possession of the server's private key.
    """

    __slots__ = ('version', 'mode', 'server_public', 'mac')

    SIZE = _SERVER_HELLO_HEAD.size + KEY_BYTES + MAC_BYTES

    def __init__(self, mode, server_public, mac, version=PROTOCOL_VERSION):
        self.version = version
        self.mode = mode
        self.server_public = server_public
        self.mac = mac

    def encode(self):
        if self.mode not in MODES:
            raise ValueError('unknown record-layer mode: %r' % (self.mode,))
        _check_key_length(self.server_public, 'server ephemeral public key')
        if len(self.mac) != MAC_BYTES:
            raise ValueError('mac must be %d bytes' % MAC_BYTES)
        flags = FLAG_FORMAT_MODE if self.mode == MODE_FORMAT else 0
        return (_SERVER_HELLO_HEAD.pack(self.version, flags)
                + bytes(self.server_public) + bytes(self.mac))

    @classmethod
    def decode(cls, data):
        if len(data) != cls.SIZE:
            raise InvalidHello('server hello is %d bytes, expected %d'
                               % (len(data), cls.SIZE))
        version, flags = _SERVER_HELLO_HEAD.unpack_from(data)
        if version != PROTOCOL_VERSION:
            raise InvalidHello('unsupported protocol version %d' % version)
        if flags & FLAG_RESERVED_MASK:
            raise InvalidHello('reserved flag bits set')
        offset = _SERVER_HELLO_HEAD.size
        return cls(mode=MODE_FORMAT if flags & FLAG_FORMAT_MODE else MODE_HYBRID,
                   server_public=data[offset:offset + KEY_BYTES],
                   mac=data[offset + KEY_BYTES:], version=version)


class SessionKeys:
    """The five keys the schedule produces, one namespace each.

    Each direction gets its own header key and body key, so a record sealed
    for one direction cannot be replayed into the other, and a
    connection-string holder cannot forge a header for someone else's stream.
    """

    __slots__ = ('auth', 'c2s_header', 'c2s_body', 's2c_header', 's2c_body')

    def __init__(self, auth, c2s_header, c2s_body, s2c_header, s2c_body):
        self.auth = auth
        self.c2s_header = c2s_header
        self.c2s_body = c2s_body
        self.s2c_header = s2c_header
        self.s2c_body = s2c_body

    def outgoing(self, is_client):
        """``(header key, body key)`` for what this end sends."""
        return ((self.c2s_header, self.c2s_body) if is_client
                else (self.s2c_header, self.s2c_body))

    def incoming(self, is_client):
        """``(header key, body key)`` for what this end receives."""
        return ((self.s2c_header, self.s2c_body) if is_client
                else (self.c2s_header, self.c2s_body))

    def __eq__(self, other):
        if not isinstance(other, SessionKeys):
            return NotImplemented
        return all(getattr(self, name) == getattr(other, name)
                   for name in self.__slots__)

    def __repr__(self):
        # Never render the keys: a SessionKeys can reach a log or a traceback.
        return '<SessionKeys (redacted)>'


def transcript_hash(server_public, client_hello_bytes, server_ephemeral_public):
    """``H = SHA-256("fteproxy/v1" || S_pub || client hello || s_pub)``.

    Binding every handshake byte into ``H``, and ``H`` into both the key
    schedule's salt and the server's MAC, is what makes a tampered hello
    produce different keys on the two ends instead of a session.
    """
    digest = hashlib.sha256()
    digest.update(_HASH_PREFIX)
    digest.update(bytes(server_public))
    digest.update(bytes(client_hello_bytes))
    digest.update(bytes(server_ephemeral_public))
    return digest.digest()


def derive_session_keys(transcript, dh_ee, dh_es):
    """Split ``HKDF-Expand(HKDF-Extract(H, DH_ee || DH_es))`` into five keys."""
    prk = _hkdf_extract(salt=transcript, ikm=dh_ee + dh_es)
    okm = _hkdf_expand(prk, _KEYS_INFO, _KEY_SCHEDULE_BYTES)
    parts = [okm[i:i + KEY_BYTES]
             for i in range(0, _KEY_SCHEDULE_BYTES, KEY_BYTES)]
    return SessionKeys(*parts)


def server_mac(keys, transcript):
    """The server hello's proof of possession, truncated to 16 bytes."""
    return _hmac_sha256(keys.auth, transcript)[:MAC_BYTES]


# --------------------------------------------------------------------------- #
# Replay filter
# --------------------------------------------------------------------------- #

class ReplayFilter:
    """Remembers the ``c_pub`` of every accepted hello inside the epoch window.

    A hello is only valid for its epoch plus or minus ``EPOCH_WINDOW`` hours,
    so a recorded hello can only be replayed inside that window, and refusing a
    repeated ``c_pub`` closes it. Entries are bucketed by epoch, so expiry is a
    dict delete rather than a scan of every key ever seen.

    Shared by every connection on a server, hence the lock.
    """

    def __init__(self, window=EPOCH_WINDOW, max_entries=REPLAY_MAX_ENTRIES):
        self._window = window
        self._max_entries = max_entries
        self._buckets = {}
        self._lock = threading.Lock()

    def observe(self, client_public, epoch, now_epoch=None):
        """Record ``client_public``; return False if it was already seen.

        Callers reject on False. Only call this once a hello has passed every
        other check, so that a malformed hello cannot fill the filter.
        """
        if now_epoch is None:
            now_epoch = current_epoch()
        key = bytes(client_public)
        with self._lock:
            self._expire(now_epoch)
            for seen in self._buckets.values():
                if key in seen:
                    return False
            self._buckets.setdefault(epoch, set()).add(key)
            self._enforce_cap()
            return True

    def _expire(self, now_epoch):
        for epoch in [e for e in self._buckets
                      if abs(e - now_epoch) > self._window]:
            del self._buckets[epoch]

    def _enforce_cap(self):
        """Bound memory under a flood of distinct ``c_pub`` values.

        The epoch a hello is filed under is chosen by the client, so eviction
        must not let one bucket push another out: dropping the *oldest* hour
        would let a flood stamped an hour in the future clear the hour real
        clients are using, and re-open replay for exactly the hellos the
        filter exists to refuse. Entries go from whichever bucket holds the
        most instead, so a flood can only displace itself, and refusing new
        clients -- which would hand an attacker a way to deny service to
        everyone else -- never happens.

        Evicting entries rather than whole buckets also bounds the filter when
        every hello names the same hour, where there is no other bucket to
        drop.
        """
        while self._total() > self._max_entries:
            epoch = max(self._buckets,
                        key=lambda e: (len(self._buckets[e]), e))
            bucket = self._buckets[epoch]
            bucket.pop()
            if not bucket:
                del self._buckets[epoch]

    def _total(self):
        return sum(len(bucket) for bucket in self._buckets.values())

    def __len__(self):
        with self._lock:
            return self._total()


# --------------------------------------------------------------------------- #
# The two halves
# --------------------------------------------------------------------------- #

class ClientHandshake:
    """The client half: build a hello, then verify the reply.

    ``ephemeral_private`` is only ever passed by the test vectors; a real
    connection draws a fresh key here and uses it once.
    """

    def __init__(self, server_public, format, mode, defs,
                 epoch=None, ephemeral_private=None):
        _check_key_length(server_public, 'server public key')
        if mode not in MODES:
            raise ValueError('unknown record-layer mode: %r' % (mode,))
        self.server_public = bytes(server_public)
        self._private = (X25519PrivateKey.from_private_bytes(ephemeral_private)
                         if ephemeral_private is not None
                         else X25519PrivateKey.generate())
        public = self._private.public_key().public_bytes_raw()
        self.hello = ClientHello(
            mode=mode, defs=int(defs), format=format, client_public=public,
            epoch=current_epoch() if epoch is None else epoch)
        self.hello_bytes = self.hello.encode()

    def finish(self, server_hello_bytes):
        """Verify the server's reply and return the :class:`SessionKeys`.

        Raises :class:`InvalidHello` if the reply is malformed, echoes a
        different mode, or carries a MAC the server could not have produced --
        which is the only evidence the client has that it is talking to the
        holder of the private key behind the connection string.
        """
        reply = ServerHello.decode(server_hello_bytes)
        if reply.mode != self.hello.mode:
            raise InvalidHello('server echoed mode %r, asked for %r'
                               % (reply.mode, self.hello.mode))
        transcript = transcript_hash(self.server_public, self.hello_bytes,
                                     reply.server_public)
        dh_ee = _x25519(self._private, reply.server_public)
        dh_es = _x25519(self._private, self.server_public)
        keys = derive_session_keys(transcript, dh_ee, dh_es)
        if not hmac.compare_digest(server_mac(keys, transcript), reply.mac):
            raise InvalidHello('server hello MAC did not verify')
        return keys


def accept_client_hello(hello_bytes, server_private, server_public,
                        defs, formats, replay=None, now_epoch=None,
                        ephemeral_private=None):
    """The server half: validate a hello and build the reply.

    Returns ``(hello, server_hello_bytes, keys)``. Every failure raises
    :class:`InvalidHello`; the caller must answer all of them identically, by
    reading and discarding rather than replying, so that a prober cannot tell
    a wrong key from a wrong format from a stale clock.

    ``formats`` is the set of base names this server serves, and ``defs`` the
    definitions release it serves them from: a client that disagrees about
    either would derive a different covertext length or regex, so the mismatch
    is refused here rather than surfacing as a stuck stream.
    """
    _check_key_length(server_private, 'server private key')
    _check_key_length(server_public, 'server public key')
    hello = ClientHello.decode(hello_bytes)
    if hello.defs != int(defs):
        raise InvalidHello('definitions release %d, this server serves %s'
                           % (hello.defs, defs))
    if hello.format not in formats:
        raise InvalidHello('unknown format base name')
    if now_epoch is None:
        now_epoch = current_epoch()
    if abs(hello.epoch - now_epoch) > EPOCH_WINDOW:
        raise InvalidHello('epoch %d is outside the window around %d'
                           % (hello.epoch, now_epoch))
    if replay is not None and not replay.observe(hello.client_public,
                                                 hello.epoch, now_epoch):
        raise ReplayedHello('client ephemeral key already seen in this window')

    private = (X25519PrivateKey.from_private_bytes(ephemeral_private)
               if ephemeral_private is not None
               else X25519PrivateKey.generate())
    public = private.public_key().public_bytes_raw()
    transcript = transcript_hash(server_public, hello_bytes, public)
    dh_ee = _x25519(private, hello.client_public)
    dh_es = _x25519(server_private, hello.client_public)
    keys = derive_session_keys(transcript, dh_ee, dh_es)
    reply = ServerHello(mode=hello.mode, server_public=public,
                        mac=server_mac(keys, transcript))
    return hello, reply.encode(), keys


def reject_delay(rng=None):
    """Seconds to keep reading and discarding before closing on a rejection.

    obfs4's behaviour: a prober that guesses wrong sees a connection that
    behaves like a service with nothing to say, and cannot time the difference
    between a wrong key and a wrong format.
    """
    raw = int.from_bytes(os.urandom(4), 'big') if rng is None else rng()
    return 1.0 + (raw % 4001) / 1000.0
