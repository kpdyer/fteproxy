#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""End-to-end relay tests: SOCKS5 and ``-L`` forwards through a real tunnel.

These build the listeners with the library API rather than the command line,
which lands in PR4. Everything runs in one process on ephemeral ports, so the
file can run alongside anything else.
"""

import socket
import struct
import threading
import time

import pytest

import fteproxy
import fteproxy.conf
import fteproxy.relay
import fteproxy.socks
import fteproxy.stream


LOCAL = '127.0.0.1'


class EchoServer(threading.Thread):
    """A destination that echoes whatever it is sent, until the peer closes."""

    daemon = True

    def __init__(self, transform=None):
        threading.Thread.__init__(self)
        self._transform = transform or (lambda data: data)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((LOCAL, 0))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._running = True

    def run(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve(self, conn):
        conn.settimeout(10)
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(self._transform(data))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._running = False


def free_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind((LOCAL, 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class Tunnel:
    """A running fteproxy server plus whatever client listeners a test adds."""

    def __init__(self, rules=None):
        self.private, self.public = fteproxy.generate_server_key()
        self.server = fteproxy.relay.ServerListener(
            LOCAL, 0, self.private, rules=rules)
        self.server.bind()
        self.server.daemon = True
        self.server.start()
        self.address = self.server.address
        self._listeners = [self.server]

    def forward(self, destination):
        listener = fteproxy.relay.ForwardListener(
            LOCAL, 0, self.address, self.public, destination=destination)
        return self._start(listener)

    def socks(self):
        listener = fteproxy.relay.SocksListener(
            LOCAL, 0, self.address, self.public)
        return self._start(listener)

    def _start(self, listener):
        listener.bind()
        listener.daemon = True
        listener.start()
        self._listeners.append(listener)
        return listener

    def stop(self):
        for listener in self._listeners:
            listener.stop()


@pytest.fixture
def echo():
    server = EchoServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def tunnel_factory():
    made = []

    def make(rules=None):
        tunnel = Tunnel(rules=rules)
        made.append(tunnel)
        return tunnel

    yield make
    for tunnel in made:
        tunnel.stop()


def socks_connect(port, host, dest_port, method=fteproxy.socks.NO_AUTHENTICATION,
                  command=fteproxy.socks.CMD_CONNECT):
    """Do a SOCKS5 CONNECT by hand; return (socket, reply status)."""
    sock = socket.create_connection((LOCAL, port), timeout=15)
    sock.settimeout(15)
    sock.sendall(bytes((fteproxy.socks.VERSION, 1, method)))
    reply = sock.recv(2)
    assert reply[0] == fteproxy.socks.VERSION
    if reply[1] != fteproxy.socks.NO_AUTHENTICATION:
        return sock, None
    sock.sendall(bytes((fteproxy.socks.VERSION, command, 0))
                 + fteproxy.stream.encode_address(host, dest_port))
    head = sock.recv(4)
    assert head[0] == fteproxy.socks.VERSION
    status = head[1]
    atyp = head[3]
    width = {fteproxy.stream.ATYP_IPV4: 4, fteproxy.stream.ATYP_IPV6: 16}.get(atyp)
    if width is None:
        width = sock.recv(1)[0]
    sock.recv(width + 2)
    return sock, status


class TestForwardListener:
    """``-L``: every local connection goes to one destination."""

    def test_round_trip(self, echo, tunnel_factory):
        tunnel = tunnel_factory(
            rules=fteproxy.stream.AllowRules(['%s:%d' % (LOCAL, echo.port)]))
        listener = tunnel.forward((LOCAL, echo.port))
        payload = b'the quick brown fox ' * 64

        sock = socket.create_connection(listener.address, timeout=15)
        sock.settimeout(15)
        try:
            sock.sendall(payload)
            received = b''
            while len(received) < len(payload):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                received += chunk
        finally:
            sock.close()
        assert received == payload

    def test_several_connections(self, echo, tunnel_factory):
        tunnel = tunnel_factory(
            rules=fteproxy.stream.AllowRules(['%s:%d' % (LOCAL, echo.port)]))
        listener = tunnel.forward((LOCAL, echo.port))
        for index in range(5):
            payload = ('connection %d' % index).encode()
            sock = socket.create_connection(listener.address, timeout=15)
            sock.settimeout(15)
            try:
                sock.sendall(payload)
                assert sock.recv(4096) == payload
            finally:
                sock.close()

    def test_half_close_reaches_the_destination(self, tunnel_factory):
        """A local shutdown(SHUT_WR) becomes a CLOSE record, and the far side
        can still answer afterwards."""
        seen = {}
        done = threading.Event()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((LOCAL, 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            conn, _ = server.accept()
            conn.settimeout(15)
            buffer = b''
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                buffer += data
            seen['before_eof'] = buffer
            conn.sendall(b'answer after your half close')
            done.set()
            time.sleep(0.5)
            conn.close()
            server.close()

        threading.Thread(target=serve, daemon=True).start()

        tunnel = tunnel_factory(
            rules=fteproxy.stream.AllowRules(['%s:%d' % (LOCAL, port)]))
        listener = tunnel.forward((LOCAL, port))
        sock = socket.create_connection(listener.address, timeout=15)
        sock.settimeout(15)
        try:
            sock.sendall(b'request')
            sock.shutdown(socket.SHUT_WR)
            assert done.wait(15), 'the destination never saw end of stream'
            assert seen['before_eof'] == b'request'
            assert sock.recv(4096) == b'answer after your half close'
        finally:
            sock.close()

    def test_refused_destination_closes_the_local_connection(self,
                                                             tunnel_factory):
        closed_port = free_port()
        tunnel = tunnel_factory(
            rules=fteproxy.stream.AllowRules(['%s:%d' % (LOCAL, closed_port)]))
        listener = tunnel.forward((LOCAL, closed_port))
        sock = socket.create_connection(listener.address, timeout=15)
        sock.settimeout(15)
        try:
            assert sock.recv(4096) == b''
        finally:
            sock.close()


class TestSocksListener:
    """``-D``: RFC 1928 CONNECT over the tunnel."""

    def test_round_trip_by_address(self, echo, tunnel_factory):
        tunnel = tunnel_factory(
            rules=fteproxy.stream.AllowRules(['%s:%d' % (LOCAL, echo.port)]))
        listener = tunnel.socks()
        sock, status = socks_connect(listener.address[1], LOCAL, echo.port)
        try:
            assert status == fteproxy.stream.SUCCEEDED
            sock.sendall(b'through SOCKS')
            assert sock.recv(4096) == b'through SOCKS'
        finally:
            sock.close()

    def test_round_trip_by_name(self, echo, tunnel_factory):
        """The name is resolved at the far end, so the client's DNS never
        leaves the tunnel."""
        tunnel = tunnel_factory(
            rules=fteproxy.stream.AllowRules(['localhost:%d' % echo.port]))
        listener = tunnel.socks()
        sock, status = socks_connect(listener.address[1], 'localhost', echo.port)
        try:
            assert status == fteproxy.stream.SUCCEEDED
            sock.sendall(b'by name')
            assert sock.recv(4096) == b'by name'
        finally:
            sock.close()

    def test_refused_port_maps_to_connection_refused(self, tunnel_factory):
        closed_port = free_port()
        tunnel = tunnel_factory(
            rules=fteproxy.stream.AllowRules(['%s:%d' % (LOCAL, closed_port)]))
        listener = tunnel.socks()
        sock, status = socks_connect(listener.address[1], LOCAL, closed_port)
        sock.close()
        assert status == fteproxy.stream.CONNECTION_REFUSED

    def test_blocked_destination_maps_to_not_allowed(self, echo,
                                                     tunnel_factory):
        """The default policy refuses the server's own loopback."""
        tunnel = tunnel_factory()
        listener = tunnel.socks()
        sock, status = socks_connect(listener.address[1], LOCAL, echo.port)
        sock.close()
        assert status == fteproxy.stream.NOT_ALLOWED

    def test_allow_rule_opts_a_local_service_back_in(self, echo,
                                                     tunnel_factory):
        tunnel = tunnel_factory(
            rules=fteproxy.stream.AllowRules(['127.0.0.1:%d' % echo.port]))
        listener = tunnel.socks()
        sock, status = socks_connect(listener.address[1], LOCAL, echo.port)
        try:
            assert status == fteproxy.stream.SUCCEEDED
            sock.sendall(b'allowed')
            assert sock.recv(4096) == b'allowed'
        finally:
            sock.close()

    def test_bind_is_not_supported(self, echo, tunnel_factory):
        tunnel = tunnel_factory(
            rules=fteproxy.stream.AllowRules(['%s:%d' % (LOCAL, echo.port)]))
        listener = tunnel.socks()
        sock, status = socks_connect(listener.address[1], LOCAL, echo.port,
                                     command=fteproxy.socks.CMD_BIND)
        sock.close()
        assert status == fteproxy.stream.COMMAND_NOT_SUPPORTED

    def test_udp_associate_is_not_supported(self, echo, tunnel_factory):
        tunnel = tunnel_factory(
            rules=fteproxy.stream.AllowRules(['%s:%d' % (LOCAL, echo.port)]))
        listener = tunnel.socks()
        sock, status = socks_connect(listener.address[1], LOCAL, echo.port,
                                     command=fteproxy.socks.CMD_UDP_ASSOCIATE)
        sock.close()
        assert status == fteproxy.stream.COMMAND_NOT_SUPPORTED

    def test_no_acceptable_method(self, tunnel_factory):
        tunnel = tunnel_factory()
        listener = tunnel.socks()
        sock, status = socks_connect(listener.address[1], LOCAL, 80, method=0x02)
        sock.close()
        assert status is None

    def test_a_non_socks_client_is_dropped(self, tunnel_factory):
        """A browser pointed at the SOCKS port by mistake is closed on, not
        answered. Either EOF or a reset is a close; which one depends on
        whether the unread request was still in the receive buffer."""
        tunnel = tunnel_factory()
        listener = tunnel.socks()
        sock = socket.create_connection(listener.address, timeout=15)
        sock.settimeout(15)
        try:
            sock.sendall(b'GET / HTTP/1.1\r\n\r\n')
            try:
                assert sock.recv(4096) == b''
            except ConnectionResetError:
                pass
        finally:
            sock.close()


class TestServerRejection:
    """A peer without the connection string gets nothing back."""

    def test_wrong_server_id_is_answered_with_silence(self, tunnel_factory,
                                                      monkeypatch):
        monkeypatch.setattr(fteproxy.handshake, 'reject_delay', lambda: 0.1)
        tunnel = tunnel_factory()
        _other_private, other_public = fteproxy.generate_server_key()
        previous = fteproxy.conf.getValue('runtime.fteproxy.negotiate.timeout')
        fteproxy.conf.setValue('runtime.fteproxy.negotiate.timeout', 1)
        try:
            client = fteproxy.wrap_socket(socket.socket(),
                                          server_id=other_public)
            with pytest.raises(fteproxy.HandshakeFailedException):
                client.connect(tunnel.address)
            client.close()
        finally:
            fteproxy.conf.setValue('runtime.fteproxy.negotiate.timeout',
                                   previous)

    def test_a_plain_tcp_probe_gets_nothing(self, tunnel_factory):
        previous = fteproxy.conf.getValue('runtime.fteproxy.negotiate.timeout')
        fteproxy.conf.setValue('runtime.fteproxy.negotiate.timeout', 1)
        try:
            tunnel = tunnel_factory()
            sock = socket.create_connection(tunnel.address, timeout=15)
            sock.settimeout(15)
            try:
                sock.sendall(b'GET / HTTP/1.0\r\n\r\n')
                assert sock.recv(4096) == b''
            finally:
                sock.close()
        finally:
            fteproxy.conf.setValue('runtime.fteproxy.negotiate.timeout',
                                   previous)


class TestStartupCheck:
    """The client's ``--no-check`` counterpart: one short session."""

    def test_check_reports_the_negotiated_session(self, tunnel_factory):
        tunnel = tunnel_factory()
        listener = tunnel.forward((LOCAL, 1))
        assert listener.check() == ('manual-http', 'hybrid')

    def test_check_fails_on_a_wrong_server_id(self, tunnel_factory):
        tunnel = tunnel_factory()
        _other_private, other_public = fteproxy.generate_server_key()
        listener = fteproxy.relay.ForwardListener(
            LOCAL, 0, tunnel.address, other_public, destination=(LOCAL, 1))
        previous = fteproxy.conf.getValue('runtime.fteproxy.negotiate.timeout')
        fteproxy.conf.setValue('runtime.fteproxy.negotiate.timeout', 1)
        try:
            with pytest.raises(fteproxy.HandshakeFailedException):
                listener.check()
        finally:
            fteproxy.conf.setValue('runtime.fteproxy.negotiate.timeout',
                                   previous)
