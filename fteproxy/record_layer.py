#!/usr/bin/env python
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
        self._buffer = ''

    def push(self, data):
        """Push data onto the FIFO buffer."""

        self._buffer += data

    def pop(self):
        """Pop data off the FIFO buffer. We pop at most
        ``runtime.fteproxy.record_layer.max_cell_size``
        bytes. The returned value is encrypted and encoded
        with ``encoder`` specified in ``__init__``.
        """
        retval = ''

        while len(self._buffer) > 0:
            plaintext = self._buffer[:MAX_CELL_SIZE]
            covertext = self._encoder.encode(plaintext)
            self._buffer = self._buffer[MAX_CELL_SIZE:]
            retval += covertext

        return retval


class Decoder:

    def __init__(
        self,
        decoder,
    ):
        self._decoder = decoder
        self._buffer = ''

    def push(self, data):
        """Push data onto the FIFO buffer."""

        self._buffer += data

    def pop(self, oneCell=False):
        """Pop data off the FIFO buffer.
        The returned value is decoded with ``_decoder`` then decrypted
        with ``_decrypter`` specified in ``__init__``.
        """

        retval = ''

        while len(self._buffer) > 0:
            try:
                msg, buffer = self._decoder.decode(self._buffer)
                retval += msg
                self._buffer = buffer
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

        return retval
