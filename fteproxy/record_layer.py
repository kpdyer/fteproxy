#!/usr/bin/env python3
# -*- coding: utf-8 -*-



import fte

import fteproxy.conf


class Encoder:

    def __init__(
        self,
        encoder,
    ):
        self._encoder = encoder
        # libfte 0.4 caps the plaintext a single covertext can carry at the
        # output format's capacity; there is no unformatted-overflow escape
        # hatch anymore. Chunk the stream to that capacity so every cell maps
        # to exactly one fixed-length covertext.
        self._capacity = encoder.max_plaintext_bytes
        self._buffer = b''

    def push(self, data):
        """Push data onto the FIFO buffer."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._buffer += data

    def pop(self):
        """Pop data off the FIFO buffer. We pop the whole buffer, sliced into
        capacity-sized chunks. Each chunk is encrypted and encoded into one
        fixed-length covertext with the ``encoder`` specified in ``__init__``.
        """
        buffer = self._buffer
        if not buffer:
            return b''

        # Encrypt each ``self._capacity`` slice via a moving offset and join the
        # cells once at the end. Slicing the head off ``self._buffer`` inside the
        # loop instead would recopy the whole remaining buffer every iteration,
        # making a single large ``push`` quadratic in the number of cells.
        cells = []
        for offset in range(0, len(buffer), self._capacity):
            plaintext = buffer[offset:offset + self._capacity]
            cells.append(self._encoder.encrypt(plaintext))

        self._buffer = b''
        return b''.join(cells)


class Decoder:

    def __init__(
        self,
        decoder,
    ):
        self._decoder = decoder
        # A fixed-length output format emits one covertext of exactly
        # ``max_length`` bytes per message, and ``decrypt`` consumes exactly one
        # such value (it does not return a remainder). The record layer therefore
        # frames the byte stream itself, slicing whole covertexts off the head of
        # the buffer and leaving any trailing partial frame for the next push.
        self._frame_size = decoder.output_format.max_length
        self._buffer = b''

    def push(self, data):
        """Push data onto the FIFO buffer."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._buffer += data

    def pop(self, oneCell=False):
        """Pop data off the FIFO buffer.
        The returned value is decrypted and decoded with ``_decoder``
        specified in ``__init__``.
        """

        # Consume whole covertext frames from a local buffer and join the decoded
        # messages once at the end; ``+= msg`` per cell would be quadratic in the
        # number of cells. ``self._buffer`` is written back once, and on a decode
        # failure it keeps the undecodable remainder (the offset does not advance
        # past a raising frame).
        buffer = self._buffer
        messages = []
        offset = 0

        while len(buffer) - offset >= self._frame_size:
            covertext = buffer[offset:offset + self._frame_size]
            try:
                msg = self._decoder.decrypt(covertext)
            except fte.MessageTooLargeError as e:
                # A complete, authenticating frame that claims a plaintext the
                # format cannot hold has no recoverable interpretation. This is
                # the successor to libfte 0.3's UnrecoverableDecryptionError, so
                # keep the fatal semantics.
                fteproxy.fatal_error("fteproxy.record_layer.MessageTooLargeError: "+str(e))
                # exit
            except fte.InvalidCovertextError as e:
                # A corrupt, wrong-format, or failed-MAC frame. Stop draining and
                # leave the bytes buffered. The negotiation scan relies on this to
                # fall through to the next candidate format.
                fteproxy.info("fteproxy.record_layer.InvalidCovertextError: "+str(e))
                break
            except fte.FTEError as e:
                fteproxy.warn("fteproxy.record_layer exception: "+str(e))
                break

            messages.append(msg)
            offset += self._frame_size

            # Stop after a single cell only once one was decoded successfully.
            # This must live outside a ``finally`` block: a ``break`` in
            # ``finally`` swallows any in-flight exception (including the
            # SystemExit raised by ``fatal_error`` on a fatal decryption error),
            # silently turning a fatal condition into a normal return.
            if oneCell:
                break

        self._buffer = buffer[offset:]
        return b''.join(messages)
