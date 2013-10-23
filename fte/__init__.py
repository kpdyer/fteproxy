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

    def __init__(self, socket, outgoing_regex, incoming_regex, K1, K2):
        self._socket = socket
        
        self._outgoing_regex = outgoing_regex
        self._incoming_regex = incoming_regex
        
        self._K1 = K1
        self._K2 = K2

        self._encrypter = fte.encrypter.Encrypter(K1 = self._K1,
                                                  K2 = self._K2)
        
        self._outgoing_encoder = fte.encoder.RegexEncoder(self._outgoing_regex)
        self._incoming_decoder = fte.encoder.RegexEncoder(self._incoming_regex)
        
        self._encoder = fte.record_layer.Encoder(encrypter=self._encrypter,
                                                 encoder=self._outgoing_encoder)
        self._decoder = fte.record_layer.Decoder(encrypter=self._encrypter,
                                                 encoder=self._incoming_decoder)

    def fileno(self):
        return self._socket.fileno()

    def accept(self):
        conn, addr = self._socket.accept()
        conn = _FTESocketWrapper(conn)
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


def wrap_socket(socket,
                outgoing_regex,
                incoming_regex,
                K1 = None, K2 = None):
    """TEST
    """
    socket_wrapped = _FTESocketWrapper(socket, outgoing_regex, incoming_regex, K1, K2)
    return socket_wrapped