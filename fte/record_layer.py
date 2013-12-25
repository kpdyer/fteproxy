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


import fte.conf


MAX_CELL_SIZE = fte.conf.getValue('runtime.fte.record_layer.max_cell_size')

class Encoder:

    def __init__(
        self,
        encrypter,
        encoder,
    ):
        self._encrypter = encrypter
        self._encoder = encoder
        self._buffer = ''

    def push(self, data):
        """Push data onto the FIFO buffer."""

        self._buffer += data

    def pop(self):
        """Pop data off the FIFO buffer. We pop at most
        ``runtime.fte.record_layer.max_cell_size``
        bytes. The returned value is encrypted with ``encrypter`` then encoded
        with ``encoder`` specified in ``__init__``.
        """
        retval = ''

        ciphertexts = []
        while len(self._buffer)>0:
            plaintext = self._buffer[:MAX_CELL_SIZE]
            self._buffer = self._buffer[MAX_CELL_SIZE:]
            ciphertext = self._encrypter.encrypt(plaintext)
            ciphertexts.append(ciphertext)
        
        covertexts = []
        for ciphertext in ciphertexts:
            covertext = self._encoder.encode(ciphertext)
            covertexts.append(covertext)
        
        retval = ''.join(covertexts)

        return retval


class Decoder:

    def __init__(
        self,
        decrypter,
        decoder,
    ):
        self._decrypter = decrypter
        self._decoder = decoder
        self._buffer = ''

    def push(self, data):
        """Push data onto the FIFO buffer."""

        self._buffer += data

    def pop(self):
        """Pop data off the FIFO buffer. We return at most
        ``runtime.fte.record_layer.max_cell_size``
        bytes. The returned value is decoded with ``encoder`` then decrypted
        with ``decrypter`` specified in ``__init__``.
        """

        retval = ''
        
        while len(self._buffer)>0:
            try:
                incoming_msg = self._decoder.decode(self._buffer)
                to_take = self._decrypter.getCiphertextLen(incoming_msg)
                ciphertext = incoming_msg[:to_take]
                retval += self._decrypter.decrypt(ciphertext)
                self._buffer = incoming_msg[to_take:]
            except fte.encoder.DecodeFailureError:
                break
            except fte.encrypter.RecoverableDecryptionError:
                break

        return retval
