#!/usr/bin/env python
# -*- coding: utf-8 -*-




import time
import socket
import random
import unittest

import fteproxy.network_io
import fteproxy.relay
import fteproxy.client
import fteproxy.server

LOCAL_INTERFACE = '127.0.0.1'


class Tests(unittest.TestCase):

    def setUp(self):
        time.sleep(1)
        self._server = fteproxy.server.listener(LOCAL_INTERFACE,
                                           fteproxy.conf.getValue(
                                               'runtime.server.port'),
                                           LOCAL_INTERFACE,
                                           fteproxy.conf.getValue('runtime.proxy.port'))
        self._client = fteproxy.client.listener(LOCAL_INTERFACE,
                                           fteproxy.conf.getValue(
                                               'runtime.client.port'),
                                           LOCAL_INTERFACE,
                                           fteproxy.conf.getValue('runtime.server.port'))

        self._server.start()
        self._client.start()

        time.sleep(1)

    def tearDown(self):
        self._server.stop()
        self._client.stop()

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
                (LOCAL_INTERFACE, fteproxy.conf.getValue('runtime.proxy.port')))
            proxy_socket.listen(fteproxy.conf.getValue('runtime.fteproxy.relay.backlog'))

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((LOCAL_INTERFACE,
                                   fteproxy.conf.getValue('runtime.client.port')))

            server_conn, addr = proxy_socket.accept()
            server_conn.settimeout(1)

            client_socket.sendall(expected_msg)
            while True:
                try:
                    data = server_conn.recv(1024)
                    if not data:
                        break
                    actual_msg += data
                    assert expected_msg.startswith(actual_msg)
                    if actual_msg == expected_msg:
                        break
                except socket.timeout:
                    continue
                except socket.error:
                    break
        except Exception as e:
            fteproxy.fatal_error("failed to transmit data: " + str(e))
        finally:
            if proxy_socket:
                fteproxy.network_io.close_socket(proxy_socket)
            if server_conn:
                fteproxy.network_io.close_socket(server_conn)
            if client_socket:
                fteproxy.network_io.close_socket(client_socket)

            self.assertEquals(expected_msg, actual_msg)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(Tests))
    return suite
