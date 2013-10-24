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
import threading

import fte.conf
import fte.encoder
import fte.io


class worker(threading.Thread):

    """This class handles relaying data between two sockets. Given socket A and
    socket B, it's the responsibility of this class to forward all incoming data
    from A to B, and all incoming data from B to A. This class is a subclass of
    threading.Thread and does not start working until start() is called. The run
    method terimates when either socket A or B is dected to be closed.
    """

    def __init__(self, socket1, socket2):
        """test"""
        threading.Thread.__init__(self)
        self._socket1 = socket1
        self._socket2 = socket2

    def run(self):
        try:
            while True:
                [success, _data] = fte.io.recvall_from_socket(self._socket1)
                if not success:
                    break
                if _data:
                    fte.io.sendall_to_socket(self._socket2, _data)

                [success, _data] = fte.io.recvall_from_socket(self._socket2)
                if not success:
                    break
                if _data:
                    fte.io.sendall_to_socket(self._socket1, _data)
        finally:
            fte.io.close_socket(self._socket1)
            fte.io.close_socket(self._socket2)


class listener(threading.Thread):

    """It's he responsibility of the listener class is to
    """

    def __init__(self, local_ip, local_port,
                 remote_ip, remote_port):
        threading.Thread.__init__(self)

        self._running = False
        self._local_ip = local_ip
        self._local_port = local_port
        self._remote_ip = remote_ip
        self._remote_port = remote_port

    def _instantiateSocket(self):
        self._sock_lock = threading.RLock()

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._local_ip, self._local_port))
        self._sock.listen(fte.conf.getValue('runtime.fte.relay.backlog'))
        self._sock.settimeout(
            fte.conf.getValue('runtime.fte.relay.socket_timeout'))

    def run(self):
        self._instantiateSocket()

        self._running = True
        while self._running:
            try:
                with self._sock_lock:
                    conn, addr = self._sock.accept()

                new_stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                new_stream.connect((self._remote_ip, self._remote_port))

                conn = self.onNewIncomingConnection(conn)
                new_stream = self.onNewOutgoingConnection(new_stream)

                w = worker(conn, new_stream)
                w.start()
            except socket.timeout:
                continue

    def stop(self):
        self._running = False
        fte.io.close_socket(self._sock,
                            lock=self._sock_lock)
