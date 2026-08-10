#!/usr/bin/env python3
# -*- coding: utf-8 -*-



import fte.encoder

import fteproxy.conf


MAX_CELL_SIZE = fteproxy.conf.getValue('runtime.fteproxy.record_layer.max_cell_size')


class Encoder:

    def __init__(
        self,
        encoder,
    ):
        self._encoder = encoder
        self._buffer = b''

    def push(self, data):
        """Push data onto the FIFO buffer."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._buffer += data

    def pop(self):
        """Pop data off the FIFO buffer. We pop at most
        ``runtime.fteproxy.record_layer.max_cell_size``
        bytes. The returned value is encrypted and encoded
        with ``encoder`` specified in ``__init__``.
        """
        buffer = self._buffer
        if not buffer:
            return b''

        # Encode each ``MAX_CELL_SIZE`` slice via a moving offset and join the
        # cells once at the end. Slicing the head off ``self._buffer`` inside the
        # loop instead would recopy the whole remaining buffer every iteration,
        # making a single large ``push`` quadratic in the number of cells.
        cells = []
        for offset in range(0, len(buffer), MAX_CELL_SIZE):
            plaintext = buffer[offset:offset + MAX_CELL_SIZE]
            cells.append(self._encoder.encode(plaintext))

        self._buffer = b''
        return b''.join(cells)


class Decoder:

    def __init__(
        self,
        decoder,
    ):
        self._decoder = decoder
        self._buffer = b''

    def push(self, data):
        """Push data onto the FIFO buffer."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._buffer += data

    def pop(self, oneCell=False):
        """Pop data off the FIFO buffer.
        The returned value is decoded with ``_decoder`` then decrypted
        with ``_decrypter`` specified in ``__init__``.
        """

        # Consume cells from a local buffer and join the decoded messages once at
        # the end; ``+= msg`` per cell would be quadratic in the number of cells.
        # ``self._buffer`` is written back once, and on a decode failure it keeps
        # the undecodable remainder (``buffer`` is unchanged by a raising decode).
        buffer = self._buffer
        messages = []

        while len(buffer) > 0:
            try:
                msg, buffer = self._decoder.decode(buffer)
                messages.append(msg)
            except fte.encoder.DecodeFailureError as e:
                fteproxy.info("fteproxy.encoder.DecodeFailure: "+str(e))
                break
            except fte.encrypter.RecoverableDecryptionError as e:
                fteproxy.info("fteproxy.encrypter.RecoverableDecryptionError: "+str(e))
                break
            except fte.encrypter.UnrecoverableDecryptionError as e:
                fteproxy.fatal_error("fteproxy.encrypter.UnrecoverableDecryptionError: "+str(e))
                # exit
            except Exception as e:
                fteproxy.warn("fteproxy.record_layer exception: "+str(e))
                break
            finally:
                if oneCell:
                    break

        self._buffer = buffer
        return b''.join(messages)
