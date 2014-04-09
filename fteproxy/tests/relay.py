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
import random
import unittest
import traceback

import fte.network_io
import fte.relay
import fte.client
import fte.server

LOCAL_INTERFACE = '127.0.0.1'


class TestRelay(unittest.TestCase):

    def setUp(self):
        time.sleep(1)
        self._server = fte.server.listener(LOCAL_INTERFACE,
                                           fte.conf.getValue(
                                               'runtime.server.port'),
                                           LOCAL_INTERFACE,
                                           fte.conf.getValue('runtime.proxy.port'))
        self._client = fte.client.listener(LOCAL_INTERFACE,
                                           fte.conf.getValue(
                                               'runtime.client.port'),
                                           LOCAL_INTERFACE,
                                           fte.conf.getValue('runtime.server.port'))

        self._server.start()
        self._client.start()

        time.sleep(1)

    def tearDown(self):
        self._server.stop()
        self._client.stop()

    def testOneStream(self):
        self._testStream()

    def testTenSerialStreams(self):
        for i in range(10):
            self._testStream()

    def _testStream(self):
        uniq_id = str(random.choice(range(2 ** 10)))
        expected_msg = 'Hello, world' * 100 + uniq_id
        actual_msg = ''

        proxy_socket = None
        client_socket = None
        server_conn = None
        try:
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            proxy_socket.bind(
                (LOCAL_INTERFACE, fte.conf.getValue('runtime.proxy.port')))
            proxy_socket.listen(fte.conf.getValue('runtime.fte.relay.backlog'))

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((LOCAL_INTERFACE,
                                   fte.conf.getValue('runtime.client.port')))

            server_conn, addr = proxy_socket.accept()
            server_conn.settimeout(
                fte.conf.getValue('runtime.fte.relay.socket_timeout'))

            client_socket.sendall(expected_msg)
            while True:
                try:
                    data = server_conn.recv(1024)
                    if not data:
                        break
                    actual_msg += data
                    if actual_msg == expected_msg:
                        break
                except socket.timeout:
                    continue
                except socket.error:
                    break
        except Exception as e:
            fte.fatal_error("failed to transmit data: " + str(e))
        finally:
            if proxy_socket:
                fte.network_io.close_socket(proxy_socket)
            if server_conn:
                fte.network_io.close_socket(server_conn)
            if client_socket:
                fte.network_io.close_socket(client_socket)

            self.assertEquals(expected_msg, actual_msg)


if __name__ == '__main__':
    unittest.main()
