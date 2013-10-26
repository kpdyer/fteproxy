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

import fte.encoder
import fte.encrypter
import fte.record_layer


class _FTESocketWrapper(object):

    def __init__(self, socket,
                 outgoing_regex, outgoing_max_len,
                 incoming_regex, incoming_max_len,
                 K1, K2):

        self._socket = socket

        self._outgoing_regex = outgoing_regex
        self._outgoing_max_len = outgoing_max_len
        self._incoming_regex = incoming_regex
        self._incoming_max_len = incoming_max_len

        self._K1 = K1
        self._K2 = K2

        self._encrypter = fte.encrypter.Encrypter(K1=self._K1,
                                                  K2=self._K2)

        self._outgoing_encoder = fte.encoder.RegexEncoder(self._outgoing_regex,
                                                          self._outgoing_max_len)
        self._incoming_decoder = fte.encoder.RegexEncoder(self._incoming_regex,
                                                          self._incoming_max_len)

        self._encoder = fte.record_layer.Encoder(encrypter=self._encrypter,
                                                 encoder=self._outgoing_encoder)
        self._decoder = fte.record_layer.Decoder(encrypter=self._encrypter,
                                                 encoder=self._incoming_decoder)

        self._incoming_buffer = ''

    def fileno(self):
        return self._socket.fileno()

    def accept(self):
        conn, addr = self._socket.accept()
        conn = _FTESocketWrapper(conn,
                                 self._outgoing_regex, self._outgoing_max_len,
                                 self._incoming_regex, self._incoming_max_len,
                                 self._K1, self._K2)
        return conn, addr

    def recv(self, bufsize):
        while True:
            data = self._socket.recv(bufsize)

            if not data and not self._incoming_buffer:
                return ''

            self._decoder.push(data)

            while True:
                frag = self._decoder.pop()
                if not frag:
                    break
                self._incoming_buffer += frag

            if self._incoming_buffer:
                break

        retval = self._incoming_buffer[:bufsize]
        self._incoming_buffer = self._incoming_buffer[bufsize:]

        return retval

    def send(self, data):
        self._encoder.push(data)
        while True:
            to_send = self._encoder.pop()
            if not to_send:
                break
            self._socket.sendall(to_send)
        return len(data)

    def sendall(self, data):
        self.send(data)
        return None

    def gettimeout(self):
        return self._socket.gettimeout()

    def settimeout(self, val):
        return self._socket.settimeout(val)

    def shutdown(self, flags):
        return self._socket.shutdown(flags)

    def close(self):
        return self._socket.close()

    def connect(self, addr):
        return self._socket.connect(addr)

    def bind(self, addr):
        return self._socket.bind(addr)

    def listen(self, N):
        return self._socket.listen(N)


def wrap_socket(socket,
                outgoing_regex, outgoing_max_len,
                incoming_regex, incoming_max_len,
                K1=None, K2=None):
    """TEST
    """
    socket_wrapped = _FTESocketWrapper(
        socket,
        outgoing_regex, outgoing_max_len,
        incoming_regex, incoming_max_len,
        K1, K2)
    return socket_wrapped
