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

import time
import socket
import threading

import fte.conf
import fte.encoder
import fte.network_io
import fte.logger


class worker(threading.Thread):

    """``fte.relay.worker`` is responsible for relaying data between two sockets. Given ``socket1`` and
    ``socket2``, the worker will forward all data
    from ``socket1`` to ``socket2``, and ``socket2`` to ``socket1``. This class is a subclass of
    threading.Thread and does not start relaying until start() is called. The run
    method terminates when either ``socket1`` or ``socket2`` is detected to be closed.
    """

    def __init__(self, socket1, socket2):
        threading.Thread.__init__(self)
        self._socket1 = socket1
        self._socket2 = socket2

    def run(self):
        """It's the responsibility of run to forward data from ``socket1`` to
        ``socket2`` and from ``socket2`` to ``socket1``. The ``run()`` method
        terminates and closes both sockets if ``fte.network_io.recvall_from_socket``
        returns a negative result for ``success``.
        """

        try:
            throttle = fte.conf.getValue('runtime.fte.relay.throttle')
            while True:
                [success, _data] = fte.network_io.recvall_from_socket(
                    self._socket1)
                if not success:
                    break
                if _data:
                    fte.network_io.sendall_to_socket(self._socket2, _data)
                else:
                    time.sleep(throttle)
        finally:
            fte.network_io.close_socket(self._socket1)
            fte.network_io.close_socket(self._socket2)


class listener(threading.Thread):

    """It's the responsibility of ``fte.relay.listener`` to bind to
    ``local_ip:local_port``. Once bound it will then relay all incoming connections
    to ``remote_ip:remote_port``.
    All new incoming connections are wrapped with ``onNewIncomingConnection``.
    All new outgoing connections are wrapped with ``onNewOutgoingConnection``.
    By default the functions ``onNewIncomingConnection`` and
    ``onNewOutgoingConnection`` are the identity function.
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
            fte.conf.getValue('runtime.fte.relay.accept_timeout'))

    def run(self):
        """Bind to ``local_ip:local_port`` and forward all connections to
        ``remote_ip:remote_port``.
        """
        self._instantiateSocket()

        self._running = True
        while self._running:
            try:
                with self._sock_lock:
                    conn, addr = self._sock.accept()

                new_stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                new_stream.connect((self._remote_ip, self._remote_port))
                fte.logger.debug("New outgoing connection established: " +
                                 str((self._remote_ip, self._remote_port)))

                conn = self.onNewIncomingConnection(conn)
                new_stream = self.onNewOutgoingConnection(new_stream)

                conn.settimeout(
                    fte.conf.getValue('runtime.fte.relay.socket_timeout'))
                new_stream.settimeout(
                    fte.conf.getValue('runtime.fte.relay.socket_timeout'))

                w1 = worker(conn, new_stream)
                w2 = worker(new_stream, conn)
                w1.start()
                w2.start()
            except socket.timeout:
                continue
            except socket.error:
                fte.logger.error("socket.error received in fte.relay")
                continue

    def stop(self):
        """Terminate the thread and stop listening on ``local_ip:local_port``.
        """
        self._running = False
        fte.network_io.close_socket(self._sock,
                                    lock=self._sock_lock)

    def onNewIncomingConnection(self, socket):
        """``onNewIncomingConnection`` returns the socket unmodified, by default we do not need to
        perform any modifications to incoming data streams.
        """

        return socket

    def onNewOutgoingConnection(self, socket):
        """``onNewOutgoingConnection`` returns the socket unmodified, by default we do not need to
        perform any modifications to incoming data streams.
        """

        return socket
