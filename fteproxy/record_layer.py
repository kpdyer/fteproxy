#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of fteproxy.
#
# fteproxy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# fteproxy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with fteproxy.  If not, see <http://www.gnu.org/licenses/>.

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

        ciphertexts = []
        while len(self._buffer) > 0:
            plaintext = self._buffer[:MAX_CELL_SIZE]
            self._buffer = self._buffer[MAX_CELL_SIZE:]
            covertext = self._encoder.encode(plaintext)
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
            except fte.encoder.DecodeFailureError:
                break
            except fte.encrypter.RecoverableDecryptionError:
                break
            except fte.encrypter.UnrecoverableDecryptionError:
                break
            except:
                break
            finally:
                if oneCell:
                    break

        return retval
