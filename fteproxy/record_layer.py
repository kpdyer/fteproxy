#!/usr/bin/env python3
# -*- coding: utf-8 -*-



import os
import struct

import fte
from cryptography.exceptions import InvalidTag

import fteproxy.conf


# Length prefix inside a sealed (random-padded) covertext plaintext.
_LEN = struct.Struct('>I')
# Sequence number inside a sealed covertext plaintext: the record's position in
# its stream. A sealed covertext therefore only unseals at that position, so a
# reordered, replayed, or dropped record is rejected in both modes (in hybrid
# mode the body MAC binds the same number).
_SEQ = struct.Struct('>Q')
_SEAL_OVERHEAD = _LEN.size + _SEQ.size
# Hybrid-mode header payload: the length of the raw body that follows it.
_OVERFLOW_LEN = struct.Struct('>I')


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
            # prefix and sequence number; the rest of the covertext capacity is
            # real payload, random-padded when the payload does not fill it.
            self._capacity = cipher.max_plaintext_bytes - _SEAL_OVERHEAD
        else:
            # 'hybrid' mode: a sealed FTE header (carrying the body length)
            # followed by the raw authenticated body. Chunk by the body's capacity, far
            # larger than a covertext's, so bulk data pays the DFA cost once per
            # record instead of once per ~150 bytes.
            self._capacity = body_cipher.max_plaintext_bytes
        self._buffer = b''
        self._seq = 0

    def push(self, data):
        """Push data onto the FIFO buffer."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._buffer += data

    def pop(self):
        """Pop the whole buffer, sliced into capacity-sized chunks and encrypted
        into one record each with the ``cipher`` (and, in hybrid mode, the
        ``body_cipher``) from ``__init__``.
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
            chunk = buffer[offset:offset + self._capacity]
            if self._body_cipher is None:
                records.append(_seal(self._cipher, chunk, self._seq))
            else:
                body = self._body_cipher.encrypt(chunk, self._seq)
                header = _seal(self._cipher, _OVERFLOW_LEN.pack(len(body)), self._seq)
                records.append(header + body)
            self._seq += 1

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
        self._buffer = b''
        self._seq = 0
        # Body length from a hybrid header that was decrypted and verified but
        # whose body had not fully arrived. While set, that header is the first
        # ``_frame_size`` bytes of ``_buffer`` (the buffer only grows).
        self._pending_body_len = None

    def push(self, data):
        """Push data onto the FIFO buffer."""
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
            # A corrupt, wrong-format, or failed-MAC frame. The negotiation scan
            # relies on this to fall through to the next candidate format.
            fteproxy.info("fteproxy.record_layer.InvalidCovertextError: "+str(e))
            return None
        except fte.FTEError as e:
            fteproxy.warn("fteproxy.record_layer exception: "+str(e))
            return None

    def pop(self, oneCell=False):
        """Pop decrypted messages off the FIFO buffer, one record at a time."""

        # Consume whole records from a local buffer and join the messages once at
        # the end; ``+= msg`` per record would be quadratic. ``self._buffer`` is
        # written back once, and the offset never advances past a record that
        # cannot (yet) be decoded, so the undecodable remainder is preserved.
        buffer = self._buffer
        messages = []
        offset = 0

        while len(buffer) - offset >= self._frame_size:
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
                    break
                head = _unseal(head, self._seq)
                if head is None:
                    # Authenticated but not a sealed record at this stream
                    # position: a peer on a different mode, corruption, or a
                    # record replayed, reordered, or dropped. Treat it as
                    # undecodable.
                    fteproxy.info(
                        "fteproxy.record_layer: malformed or out-of-order sealed "
                        "record at seq " + str(self._seq))
                    break

                if self._body_cipher is None:
                    # 'format' mode: the sealed covertext carried the message.
                    messages.append(head)
                    offset += self._frame_size
                    self._seq += 1
                    if oneCell:
                        break
                    continue

                # 'hybrid' mode: the header carries the raw body's length. The
                # header is authenticated, so a successful decrypt means we
                # wrote it and the length is trustworthy.
                if len(head) != _OVERFLOW_LEN.size:
                    fteproxy.info(
                        "fteproxy.record_layer: unexpected header width "
                        + str(len(head)))
                    break
                body_len = _OVERFLOW_LEN.unpack(head)[0]
                if body_len > self._body_cipher.max_framed_bytes:
                    # The header authenticates, so only a key holder can send
                    # this, but never buffer up to 4 GiB on its say-so.
                    fteproxy.info(
                        "fteproxy.record_layer: body length " + str(body_len)
                        + " exceeds the record limit")
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
                msg = self._body_cipher.decrypt(body, self._seq)
            except InvalidTag:
                # Wrong key, corruption, or a record out of its stream
                # position (reorder/drop/replay). Stop draining.
                fteproxy.info(
                    "fteproxy.record_layer: body auth failed at seq "
                    + str(self._seq))
                break
            self._seq += 1
            messages.append(msg)
            offset = body_start + body_len

            # Stop after a single record only once one decoded successfully. This
            # must live here, not in a ``finally``: a ``break`` in ``finally``
            # swallows any in-flight exception (including the SystemExit raised by
            # ``fatal_error``), silently turning a fatal condition into a return.
            if oneCell:
                break

        self._buffer = buffer[offset:]
        return b''.join(messages)
