#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration tests for the FTE relay (client/server communication).
"""

import time
import socket
import random

import pytest

import fteproxy
import fteproxy.conf
import fteproxy.network_io
import fteproxy.relay
import fteproxy.client
import fteproxy.server


LOCAL_INTERFACE = '127.0.0.1'


@pytest.fixture
def relay_setup():
    """Set up client and server for relay testing."""
    time.sleep(1)
    
    server = fteproxy.server.listener(
        LOCAL_INTERFACE,
        fteproxy.conf.getValue('runtime.server.port'),
        LOCAL_INTERFACE,
        fteproxy.conf.getValue('runtime.proxy.port')
    )
    client = fteproxy.client.listener(
        LOCAL_INTERFACE,
        fteproxy.conf.getValue('runtime.client.port'),
        LOCAL_INTERFACE,
        fteproxy.conf.getValue('runtime.server.port')
    )
    
    server.start()
    client.start()
    time.sleep(1)
    
    yield {'server': server, 'client': client}
    
    # Cleanup
    server.stop()
    client.stop()


class TestRelay:
    """Integration tests for FTE relay."""

    def test_serial_streams(self, relay_setup):
        """Test multiple serial data streams through the relay."""
        for i in range(10):
            self._test_single_stream()

    def _test_single_stream(self):
        """Test a single data stream through the relay."""
        uniq_id = str(random.choice(range(2 ** 10)))
        expected_msg = ('Hello, world' * 100 + uniq_id).encode('utf-8')
        actual_msg = b''

        proxy_socket = None
        client_socket = None
        server_conn = None
        
        try:
            # Set up proxy socket (destination)
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            proxy_socket.bind((LOCAL_INTERFACE, fteproxy.conf.getValue('runtime.proxy.port')))
            proxy_socket.listen(fteproxy.conf.getValue('runtime.fteproxy.relay.backlog'))

            # Connect client
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((LOCAL_INTERFACE, fteproxy.conf.getValue('runtime.client.port')))

            # Accept connection on proxy side
            server_conn, addr = proxy_socket.accept()
            server_conn.settimeout(1)

            # Send data through the relay
            client_socket.sendall(expected_msg)
            
            # Receive data on the other side
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
            pytest.fail(f"Failed to transmit data: {e}")
            
        finally:
            if proxy_socket:
                fteproxy.network_io.close_socket(proxy_socket)
            if server_conn:
                fteproxy.network_io.close_socket(server_conn)
            if client_socket:
                fteproxy.network_io.close_socket(client_socket)

        assert expected_msg == actual_msg
