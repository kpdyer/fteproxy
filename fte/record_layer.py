#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of FTE.
#
# FTE is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# FTE is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with FTE.  If not, see <http://www.gnu.org/licenses/>.


import fte.conf


MAX_CELL_SIZE = fte.conf.getValue('runtime.fte.record_layer.max_cell_size')


class PopFailedException(Exception):
    pass


class Encoder:

    def __init__(
        self,
        encrypter,
    ):
        self._encrypter = encrypter
        self._buffer = ''

    def push(self, data):
        self._buffer += data

    def pop(self):
        retval = ''
        outgoing_msg = self._buffer[:MAX_CELL_SIZE]
        self._buffer = self._buffer[MAX_CELL_SIZE:]
        if outgoing_msg:
            retval = self._encrypter.encrypt(outgoing_msg)

        return retval


class Decoder:

    def __init__(
        self,
        encrypter,
    ):
        self._encrypter = encrypter
        self._buffer = ''

    def push(self, data):
        self._buffer += data

    def pop(self):
        retval = ''
        if self._buffer:
            frag = fte.bit_ops.bytes_to_long(self._buffer)
            to_take = self._encrypter.getMessageLen(
                len(self._buffer) * 8, frag) + 41
            to_decrypt = self._buffer[:to_take]
            self._buffer = self._buffer[to_take:]
            retval = self._encrypter.decrypt(len(to_decrypt) * 8, to_decrypt)
        return retval
