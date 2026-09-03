#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The record layer: frames a byte stream as a sequence of libfte covertexts.

libfte 0.4 encrypts one message into exactly one fixed-length covertext and
has no stream framing of its own, so this module defines the wire layout.
Every record starts with a *sealed* covertext of exactly ``length`` bytes (the
format's fixed covertext length): its plaintext is
``len(4) || seq(8) || message || random pad`` filled to the format's capacity,
so it reads as random format text and only unseals at stream position
``seq``. The two modes differ in what the sealed covertext carries:

``format``
    The message itself. The stream is a sequence of covertexts, all in the
    target format.

``hybrid`` (the default)
    A 4-byte body length, followed on the wire by that many raw bytes:
    ``nonce(12) || AES-128-CTR ciphertext || HMAC-SHA256 tag(16)`` from
    :class:`fteproxy._AEADBody`, with ``seq`` bound into the tag. Only the
    header blends in with the format; the body is high-entropy ciphertext.

The message itself begins with a one-byte record type (:data:`DATA` and the
other constants below), so one connection carries application bytes, stream
control and future padding without a second framing layer. In ``format`` mode
that byte is the first byte inside the sealed covertext; in ``hybrid`` mode it
is the first byte of the raw body. Either way the sealed ``len`` and ``seq``
fields are unchanged, so chunking, buffering and the body-length bound are the
same as they were before types existed.

``seq`` is the record's position in its stream, counted from 0 by each
``Encoder``/``Decoder`` pair, so a record moved, replayed, or dropped within
a stream is rejected. Since 1.0 each direction of a connection has its own
header and body keys, derived per connection by :mod:`fteproxy.handshake`, so
a record cannot be replayed into another stream or the other direction either.
See SECURITY.md for what is not covered.
"""

import os
import struct

import fte
from cryptography.exceptions import InvalidTag

import fteproxy.conf


#: Application bytes.
DATA = 0x00
#: Open a stream to the destination in the payload (see ``fteproxy.stream``).
OPEN = 0x01
#: The status of an :data:`OPEN`.
OPEN_RESULT = 0x02
#: Ignored on receipt; reserved for traffic shaping.
PADDING = 0x03
#: The sender will send no more :data:`DATA` on this connection.
CLOSE = 0x04

RECORD_TYPES = frozenset((DATA, OPEN, OPEN_RESULT, PADDING, CLOSE))

# Length prefix inside a sealed (random-padded) covertext plaintext.
_LEN = struct.Struct('>I')
# Sequence number inside a sealed covertext plaintext: the record's position in
# its stream. A sealed covertext therefore only unseals at that position, so a
# reordered, replayed, or dropped record is rejected in both modes (in hybrid
# mode the body MAC binds the same number).
_SEQ = struct.Struct('>Q')
_SEAL_OVERHEAD = _LEN.size + _SEQ.size
# The record type byte that leads every message.
_TYPE_LEN = 1
# Hybrid-mode header payload: the length of the raw body that follows it.
_OVERFLOW_LEN = struct.Struct('>I')


class UnknownRecordType(Exception):
    """An authenticated record whose type this version does not define.

    Only a peer holding the session keys can produce one, so this is a version
    mismatch rather than an attack, and the connection is closed: continuing
    would mean guessing at the meaning of the bytes that follow.
    """


class StreamFailedError(Exception):
    """Data was pushed into a :class:`Decoder` after one of its records
    failed authentication. The stream cannot resume; close the connection."""


def _seal(cipher, message, seq):
    """Encrypt ``message`` into one covertext, random-padded to the format's
    full plaintext capacity and stamped with its stream position ``seq``.

    A short message otherwise ranks low and unranks into a covertext with a long
    run of the format's lowest character (the ``GET /0000...`` padding). Filling
    the plaintext to capacity makes the covertext use its whole rank space, so it
    reads as random format text and no longer leaks the message length through
    its rank. The random pad sits inside the authenticated ciphertext, so it
    costs nothing on the wire (the covertext is a fixed length either way) and
    reveals nothing.
    """
    plaintext = _LEN.pack(len(message)) + _SEQ.pack(seq) + message
    pad = cipher.max_plaintext_bytes - len(plaintext)
    if pad > 0:
        plaintext += os.urandom(pad)
    return cipher.encrypt(plaintext)


def _unseal(plaintext, seq):
    """Recover the message from a sealed plaintext, or ``None`` if it is
    malformed or was sealed at a stream position other than ``seq``."""
    if len(plaintext) < _SEAL_OVERHEAD:
        return None
    length = _LEN.unpack_from(plaintext)[0]
    if _SEQ.unpack_from(plaintext, _LEN.size)[0] != seq:
        return None
    if length > len(plaintext) - _SEAL_OVERHEAD:
        return None
    return plaintext[_SEAL_OVERHEAD:_SEAL_OVERHEAD + length]


class Encoder:

    def __init__(
        self,
        cipher,
        body_cipher=None,
    ):
        self._cipher = cipher
        self._body_cipher = body_cipher
        if body_cipher is None:
            # 'format' mode: one sealed covertext per chunk. Reserve the length
            # prefix, sequence number and record type; the rest of the covertext
            # capacity is real payload, random-padded when the payload does not
            # fill it.
            self._capacity = (cipher.max_plaintext_bytes
                              - _SEAL_OVERHEAD - _TYPE_LEN)
        else:
            # 'hybrid' mode: a sealed FTE header (carrying the body length)
            # followed by the raw authenticated body. Chunk by the body's capacity, far
            # larger than a covertext's, so bulk data pays the DFA cost once per
            # record instead of once per ~150 bytes. The type byte rides on top
            # of the body rather than coming out of the payload, so the chunk
            # boundaries are exactly where they were before types existed.
            self._capacity = body_cipher.max_plaintext_bytes
        if self._capacity < 1:
            raise ValueError('format is too small to carry a record')
        self._buffer = b''
        self._seq = 0

    @property
    def capacity(self):
        """The largest payload one record of this stream can carry."""
        return self._capacity

    def _emit(self, record_type, payload):
        """One complete record on the wire, advancing the stream position."""
        message = bytes((record_type,)) + payload
        if self._body_cipher is None:
            record = _seal(self._cipher, message, self._seq)
        else:
            body = self._body_cipher.encrypt(message, self._seq)
            record = (_seal(self._cipher, _OVERFLOW_LEN.pack(len(body)),
                            self._seq)
                      + body)
        self._seq += 1
        return record

    def encode(self, record_type, payload=b''):
        """Encode one record of any type. Control messages go out this way;
        :meth:`pop` is the bulk path for :data:`DATA`."""
        if record_type not in RECORD_TYPES:
            raise ValueError('unknown record type: %r' % (record_type,))
        if len(payload) > self._capacity:
            raise ValueError('payload of %d bytes exceeds the %d-byte record '
                             'capacity' % (len(payload), self._capacity))
        return self._emit(record_type, payload)

    def push(self, data):
        """Push data onto the FIFO buffer."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._buffer += data

    def pop(self):
        """Pop the whole buffer, sliced into capacity-sized chunks and encrypted
        into one :data:`DATA` record each with the ``cipher`` (and, in hybrid
        mode, the ``body_cipher``) from ``__init__``.
        """
        buffer = self._buffer
        if not buffer:
            return b''

        # Encrypt each ``self._capacity`` slice via a moving offset and join the
        # records once at the end. Slicing the head off ``self._buffer`` inside
        # the loop instead would recopy the whole remaining buffer every
        # iteration, making a single large ``push`` quadratic.
        records = []
        for offset in range(0, len(buffer), self._capacity):
            records.append(
                self._emit(DATA, buffer[offset:offset + self._capacity]))

        self._buffer = b''
        return b''.join(records)


class Decoder:

    def __init__(
        self,
        cipher,
        body_cipher=None,
    ):
        self._cipher = cipher
        self._body_cipher = body_cipher
        # A fixed-length output format emits one covertext of exactly
        # ``max_length`` bytes, and ``decrypt`` consumes exactly one such value
        # (no remainder). The record layer frames the byte stream itself: in
        # 'format' mode a record is that one covertext; in 'hybrid' mode it is
        # the header covertext plus the ``body_len`` raw bytes the header carries.
        # Either way a trailing partial record stays buffered.
        self._frame_size = cipher.output_format.max_length
        # The largest record this decoder is ever asked to hold: one header
        # covertext plus, in hybrid mode, the largest framed body a header may
        # announce. After every pop the buffer is shorter than this, so a
        # stream that fails to authenticate cannot grow the buffer without
        # bound (see the fail-closed behavior below).
        self.max_record_bytes = self._frame_size + (
            body_cipher.max_framed_bytes if body_cipher is not None else 0)
        self._buffer = b''
        self._seq = 0
        # Set once a record fails to authenticate: nothing later can decode,
        # since the sequence number cannot advance past the bad record, so the
        # stream is dead and push refuses further input.
        self._failed = False
        # Body length from a hybrid header that was decrypted and verified but
        # whose body had not fully arrived. While set, that header is the first
        # ``_frame_size`` bytes of ``_buffer`` (the buffer only grows).
        self._pending_body_len = None

    @property
    def failed(self):
        """Whether a record failed to authenticate and the stream is dead."""
        return self._failed

    def push(self, data):
        """Push data onto the FIFO buffer.

        Raises :class:`StreamFailedError` once the stream has failed: nothing
        pushed after a bad record could decode, and buffering it would let a
        peer that holds the keys grow the buffer without bound.
        """
        if self._failed:
            raise StreamFailedError('data pushed after a record failed to '
                                    'authenticate')
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._buffer += data

    def _decrypt(self, cipher, covertext):
        """Decrypt one covertext, mapping libfte errors to fteproxy semantics.

        Returns the plaintext, or ``None`` if the frame is not (yet) decodable
        and the caller should stop draining and keep it buffered.
        """
        try:
            return cipher.decrypt(covertext)
        except fte.FormatContractError as e:
            # The format provider broke the RankedFormat contract: a bug in the
            # format, not bad input, so no frame can be trusted. Keep libfte
            # 0.3's UnrecoverableDecryptionError semantics and stop the process.
            # (In 0.4, decrypt never raises MessageTooLargeError; that is an
            # encrypt-side limit. A corrupt or oversized covertext is the
            # InvalidCovertextError below.)
            fteproxy.fatal_error("fteproxy.record_layer.FormatContractError: "+str(e))
            # exit
        except fte.InvalidCovertextError as e:
            # A corrupt, wrong-format, or failed-MAC frame. The server's
            # first-record scan relies on this to fall through to the next
            # candidate format.
            fteproxy.debug("fteproxy.record_layer.InvalidCovertextError: "+str(e))
            return None
        except fte.FTEError as e:
            fteproxy.warn("fteproxy.record_layer exception: "+str(e))
            return None

    @staticmethod
    def _split_type(message):
        """``type || payload`` -> ``(type, payload)``, checking the type."""
        if not message:
            raise UnknownRecordType('empty record')
        record_type = message[0]
        if record_type not in RECORD_TYPES:
            raise UnknownRecordType('record type 0x%02x' % record_type)
        return record_type, message[1:]

    def pop_records(self, limit=None):
        """Pop decoded records off the FIFO buffer as ``(type, payload)``.

        Stops at ``limit`` records, or when the next record is incomplete or
        undecodable. Raises :class:`UnknownRecordType` for an authenticated
        record this version does not define; the caller closes the connection.
        """

        # Consume whole records from a local buffer and collect the messages,
        # writing ``self._buffer`` back once. The offset never advances past a
        # record that cannot (yet) be decoded, so the undecodable remainder is
        # preserved.
        if self._failed:
            return []
        buffer = self._buffer
        records = []
        offset = 0

        while len(buffer) - offset >= self._frame_size:
            if limit is not None and len(records) >= limit:
                break
            if self._body_cipher is not None and self._pending_body_len is not None:
                # The header at the front of the buffer was decrypted and
                # verified on an earlier pop whose body had not fully arrived.
                # A large record arrives over several reads, so do not rank
                # and verify the same header again for each partial delivery.
                body_len = self._pending_body_len
            else:
                header = buffer[offset:offset + self._frame_size]
                head = self._decrypt(self._cipher, header)
                if head is None:
                    self._failed = True
                    break
                head = _unseal(head, self._seq)
                if head is None:
                    # Authenticated but not a sealed record at this stream
                    # position: a peer on a different mode, corruption, or a
                    # record replayed, reordered, or dropped. Treat it as
                    # undecodable.
                    fteproxy.debug(
                        "fteproxy.record_layer: malformed or out-of-order sealed "
                        "record at seq " + str(self._seq))
                    self._failed = True
                    break

                if self._body_cipher is None:
                    # 'format' mode: the sealed covertext carried the message.
                    self._seq += 1
                    offset += self._frame_size
                    records.append(self._split_type(head))
                    continue

                # 'hybrid' mode: the header carries the raw body's length. The
                # header is authenticated, so a successful decrypt means we
                # wrote it and the length is trustworthy.
                if len(head) != _OVERFLOW_LEN.size:
                    fteproxy.debug(
                        "fteproxy.record_layer: unexpected header width "
                        + str(len(head)))
                    self._failed = True
                    break
                body_len = _OVERFLOW_LEN.unpack(head)[0]
                if body_len > self._body_cipher.max_framed_bytes:
                    # The header authenticates, so only a key holder can send
                    # this, but never buffer up to 4 GiB on its say-so.
                    fteproxy.info(
                        "fteproxy.record_layer: body length " + str(body_len)
                        + " exceeds the record limit")
                    self._failed = True
                    break

            body_start = offset + self._frame_size
            if len(buffer) - body_start < body_len:
                # Body not fully arrived; wait for more data. The write-back
                # below leaves this header at the front of the buffer.
                self._pending_body_len = body_len
                break
            self._pending_body_len = None
            body = buffer[body_start:body_start + body_len]
            try:
                message = self._body_cipher.decrypt(body, self._seq)
            except InvalidTag:
                # Wrong key, corruption, or a record out of its stream
                # position (reorder/drop/replay). Stop draining.
                fteproxy.debug(
                    "fteproxy.record_layer: body auth failed at seq "
                    + str(self._seq))
                self._failed = True
                break
            self._seq += 1
            offset = body_start + body_len
            records.append(self._split_type(message))

        self._buffer = b'' if self._failed else buffer[offset:]
        return records

    def pop(self, limit=None):
        """The :data:`DATA` payloads from :meth:`pop_records`, concatenated.

        For callers that carry nothing but application bytes. A control record
        raises, because silently dropping one would lose a stream's OPEN or its
        half-close.
        """
        records = self.pop_records(limit=limit)
        for record_type, _payload in records:
            if record_type != DATA:
                raise UnknownRecordType(
                    'unexpected control record 0x%02x on a data-only stream'
                    % record_type)
        return b''.join(payload for _type, payload in records)
