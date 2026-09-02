#!/usr/bin/env python3
# -*- coding: utf-8 -*-



import struct

import fte

import fteproxy.conf


# Hybrid-mode header: a fixed-width big-endian body length. The header is one
# FTE-formatted covertext; the body that follows it is `body_len` raw bytes.
_BODY_LEN = struct.Struct('>I')


class Encoder:

    def __init__(
        self,
        cipher,
        body_cipher=None,
    ):
        self._cipher = cipher
        self._body_cipher = body_cipher
        # 'format' mode: one fixed-length covertext per capacity-sized chunk, the
        # whole covertext transformed into the target format.
        # 'hybrid' mode: a fixed-length FTE header (carrying the body length)
        # followed by the raw BytesFormat body. Chunk by the body's capacity,
        # which is far larger (~1 MiB) than a formatted covertext's, so bulk data
        # pays the DFA cost once per record instead of once per ~150 bytes.
        carrier = body_cipher if body_cipher is not None else cipher
        self._capacity = carrier.max_plaintext_bytes
        self._buffer = b''

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
                records.append(self._cipher.encrypt(chunk))
            else:
                body = self._body_cipher.encrypt(chunk)
                header = self._cipher.encrypt(_BODY_LEN.pack(len(body)))
                records.append(header + body)

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
        # the fixed-length header covertext plus the ``body_len`` raw bytes the
        # header carries. Either way a trailing partial record stays buffered.
        self._frame_size = cipher.output_format.max_length
        self._buffer = b''

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
        except fte.MessageTooLargeError as e:
            # A complete, authenticating frame that claims a plaintext the format
            # cannot hold has no recoverable interpretation. This is the
            # successor to libfte 0.3's UnrecoverableDecryptionError, so keep the
            # fatal semantics.
            fteproxy.fatal_error("fteproxy.record_layer.MessageTooLargeError: "+str(e))
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
            header = buffer[offset:offset + self._frame_size]
            head = self._decrypt(self._cipher, header)
            if head is None:
                break

            if self._body_cipher is None:
                # 'format' mode: the header covertext IS the message.
                messages.append(head)
                offset += self._frame_size
            else:
                # 'hybrid' mode: the header carries the raw body's length. The
                # header is authenticated, so a successful decrypt means we wrote
                # it and the length is trustworthy. A header that authenticates
                # but is not exactly the expected width is a peer running a
                # different mode (or corruption); treat it as undecodable.
                if len(head) != _BODY_LEN.size:
                    fteproxy.info(
                        "fteproxy.record_layer: unexpected header width "
                        + str(len(head)))
                    break
                body_len = _BODY_LEN.unpack(head)[0]
                body_start = offset + self._frame_size
                if len(buffer) - body_start < body_len:
                    break  # body not fully arrived; wait for more data
                body = buffer[body_start:body_start + body_len]
                msg = self._decrypt(self._body_cipher, body)
                if msg is None:
                    break
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
