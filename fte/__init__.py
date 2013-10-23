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

import socket

import fte.encrypter
import fte.record_layer

class _FTESocketWrapper(object):

    def __init__(self, socket, regex):
        self._socket = socket
        self._regex = regex

        self._encrypter = fte.encrypter.Encrypter()
        self._regex_encoder = fte.encoder.RegexEncoder(
            "intersection-http-request")
        self._encoder = fte.record_layer.Encoder(encrypter=self._encrypter,
                                                 encoder=self._regex_encoder)
        self._decoder = fte.record_layer.Decoder(encrypter=self._encrypter,
                                                 encoder=self._regex_encoder)

    def fileno(self):
        return self._socket.fileno()

    def accept(self):
        conn, addr = self._socket.accept()
        conn = FTESocketWrapper(conn)
        return conn, addr

    def recv(self, bufsize):
        retval = ''
        data = self._socket.recv(bufsize)
        self._decoder.push(data)
        while True:
            frag = self._decoder.pop()
            if not frag:
                break
            retval += frag
        if retval == '':
            raise socket.timeout
        return retval

    def send(self, data):
        self._encoder.push(data)
        while True:
            to_send = self._encoder.pop()
            if not to_send:
                break
            self._socket.sendall(to_send)
        return len(data)

    def gettimeout(self):
        return self._socket.gettimeout()

    def settimeout(self, val):
        return self._socket.settimeout(val)

    def shutdown(self, flags):
        return self._socket.shutdown(flags)

    def close(self):
        return self._socket.close()


def wrap_socket(socket, regex):
    """TEST
    """
    socket_wrapped = _FTESocketWrapper(socket, regex)
    return socket_wrapped