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


def _read_until_eof(sock, timeout=10):
    """Read from ``sock`` until the peer's EOF; fail instead of hanging."""
    deadline = time.time() + timeout
    received = b''
    sock.settimeout(1)
    while True:
        if time.time() > deadline:
            pytest.fail("no EOF within %ss; received %r" % (timeout, received))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            return received
        received += chunk


class TestWorkerHalfClose:
    """``relay.worker`` forwards a TCP half-close instead of tearing the
    connection down (plain sockets, no FTE layer).

    Regression test: a worker used to close BOTH sockets as soon as its own
    read side reported EOF, so an application that sent a request and
    ``shutdown(SHUT_WR)`` never got the reply flowing the other way.
    """

    def _relay(self):
        app, conn = socket.socketpair()
        new_stream, dest = socket.socketpair()
        for s in (conn, new_stream):
            s.settimeout(fteproxy.conf.getValue('runtime.fteproxy.relay.socket_timeout'))
        w1, w2 = fteproxy.relay.worker.pair(conn, new_stream)
        w1.start()
        w2.start()
        return app, dest, conn, new_stream, w1, w2

    def test_half_close_keeps_reverse_direction_open(self):
        app, dest, conn, new_stream, w1, w2 = self._relay()
        try:
            app.sendall(b'request-body')
            app.shutdown(socket.SHUT_WR)

            # The half-close arrives after every byte sent before it.
            assert _read_until_eof(dest) == b'request-body'

            # The reverse direction is still relaying.
            dest.sendall(b'REPLY-TO:request-body')
            dest.close()
            assert _read_until_eof(app) == b'REPLY-TO:request-body'

            # Now both directions are done: the workers exit and the relay
            # sockets are closed.
            w1.join(5)
            w2.join(5)
            assert not w1.is_alive() and not w2.is_alive()
            assert conn.fileno() == -1 and new_stream.fileno() == -1
        finally:
            for s in (app, dest, conn, new_stream):
                fteproxy.network_io.close_socket(s)

    def test_error_closes_both_directions(self):
        class _BrokenSend:
            """socket2 stand-in whose sendall fails, like a peer that reset."""

            def __init__(self, sock):
                self._sock = sock

            def sendall(self, data):
                raise OSError('simulated send failure')

            def __getattr__(self, name):
                return getattr(self._sock, name)

        app, conn = socket.socketpair()
        new_stream, dest = socket.socketpair()
        conn.settimeout(1)
        new_stream.settimeout(1)
        w1, w2 = fteproxy.relay.worker.pair(conn, _BrokenSend(new_stream))
        w1.start()
        w2.start()
        try:
            # The forward direction fails while the reverse one is idle: the
            # failure must close the whole connection, both peers see EOF.
            app.sendall(b'request-body')
            assert _read_until_eof(app) == b''
            assert _read_until_eof(dest) == b''
            w1.join(5)
            w2.join(5)
            assert not w1.is_alive() and not w2.is_alive()
            assert conn.fileno() == -1 and new_stream.fileno() == -1
        finally:
            for s in (app, dest, conn, new_stream):
                fteproxy.network_io.close_socket(s)

    def test_lone_worker_closes_both_on_eof(self):
        """A worker without a sibling still owns the connection alone."""
        app, conn = socket.socketpair()
        new_stream, dest = socket.socketpair()
        conn.settimeout(1)
        new_stream.settimeout(1)
        w = fteproxy.relay.worker(conn, new_stream)
        w.start()
        try:
            app.sendall(b'one-way')
            app.shutdown(socket.SHUT_WR)
            assert _read_until_eof(dest) == b'one-way'
            w.join(5)
            assert not w.is_alive()
            assert conn.fileno() == -1 and new_stream.fileno() == -1
        finally:
            for s in (app, dest, conn, new_stream):
                fteproxy.network_io.close_socket(s)


class TestRelayHalfClose:
    """A request/response exchange that relies on TCP half-close works through
    a real fteproxy client/server pair (``echo x | nc host port``, HTTP/1.0).
    """

    def test_half_close_round_trip(self, relay_setup):
        request = b'request-body'
        dest_listener = None
        app = None
        dest = None
        try:
            dest_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dest_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            dest_listener.bind((LOCAL_INTERFACE, fteproxy.conf.getValue('runtime.proxy.port')))
            dest_listener.listen(fteproxy.conf.getValue('runtime.fteproxy.relay.backlog'))
            dest_listener.settimeout(10)

            app = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            app.connect((LOCAL_INTERFACE, fteproxy.conf.getValue('runtime.client.port')))

            dest, _ = dest_listener.accept()

            # The application sends its request and half-closes, then waits
            # for the reply; the destination reads to EOF before answering.
            app.sendall(request)
            app.shutdown(socket.SHUT_WR)

            assert _read_until_eof(dest) == request
            dest.sendall(b'REPLY-TO:' + request)
            dest.close()

            assert _read_until_eof(app) == b'REPLY-TO:' + request
        finally:
            for s in (app, dest, dest_listener):
                if s is not None:
                    fteproxy.network_io.close_socket(s)

    def test_half_close_without_data(self, relay_setup):
        """A half-close before any payload (``nc host port < /dev/null``) still
        reaches the destination: the negotiation cell is flushed ahead of the
        FIN, so the server side sees a live, negotiated stream.
        """
        dest_listener = None
        app = None
        dest = None
        try:
            dest_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dest_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            dest_listener.bind((LOCAL_INTERFACE, fteproxy.conf.getValue('runtime.proxy.port')))
            dest_listener.listen(fteproxy.conf.getValue('runtime.fteproxy.relay.backlog'))
            dest_listener.settimeout(10)

            app = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            app.connect((LOCAL_INTERFACE, fteproxy.conf.getValue('runtime.client.port')))

            dest, _ = dest_listener.accept()

            app.shutdown(socket.SHUT_WR)

            assert _read_until_eof(dest) == b''
            dest.sendall(b'banner-after-eof')
            dest.close()

            assert _read_until_eof(app) == b'banner-after-eof'
        finally:
            for s in (app, dest, dest_listener):
                if s is not None:
                    fteproxy.network_io.close_socket(s)
