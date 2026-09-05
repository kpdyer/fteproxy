#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exercise SOCKS5, forwarding, admission, and shutdown through real listeners.

Use the library API on ephemeral local ports. test_system.py covers CLI
subprocesses; these tests also share process-level configuration and caches.
"""

import socket
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


def wait_until(predicate, timeout=5):
    """Wait for a listener thread to reach an observable bookkeeping state."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


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
        """The server resolves the requested name; its address rule permits loopback."""
        tunnel = tunnel_factory(
            rules=fteproxy.stream.AllowRules([
                'localhost:%d' % echo.port,
                '127.0.0.1:%d' % echo.port,
            ]))
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
        previous = fteproxy.conf.getValue('runtime.fteproxy.handshake.timeout')
        fteproxy.conf.setValue('runtime.fteproxy.handshake.timeout', 1)
        try:
            client = fteproxy.wrap_socket(socket.socket(),
                                          server_id=other_public)
            with pytest.raises(fteproxy.HandshakeFailedException):
                client.connect(tunnel.address)
            client.close()
        finally:
            fteproxy.conf.setValue('runtime.fteproxy.handshake.timeout',
                                   previous)

    def test_a_plain_tcp_probe_gets_nothing(self, tunnel_factory):
        previous = fteproxy.conf.getValue('runtime.fteproxy.handshake.timeout')
        fteproxy.conf.setValue('runtime.fteproxy.handshake.timeout', 1)
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
            fteproxy.conf.setValue('runtime.fteproxy.handshake.timeout',
                                   previous)


class TestServerAdmission:
    """Slow unauthenticated peers cannot create unbounded setup threads."""

    @staticmethod
    def _server(max_pending, per_source):
        private, _public = fteproxy.generate_server_key()
        server = fteproxy.relay.ServerListener(
            LOCAL, 0, private, max_pending=max_pending,
            max_pending_per_source=per_source)
        server.bind()
        server.daemon = True
        server.start()
        return server

    @staticmethod
    def _is_closed(sock):
        try:
            return sock.recv(1) == b''
        except ConnectionResetError:
            return True
        except socket.timeout:
            return False

    def test_per_source_excess_is_closed_before_a_worker(self):
        server = self._server(max_pending=4, per_source=1)
        first = socket.create_connection(server.address, timeout=5)
        first.settimeout(0.25)
        second = None
        try:
            assert wait_until(lambda: server._setup_admission._total == 1)
            second = socket.create_connection(server.address, timeout=5)
            second.settimeout(2)
            assert wait_until(lambda: self._is_closed(second), timeout=2)
            assert server._setup_admission._total == 1
        finally:
            first.close()
            if second is not None:
                second.close()
            server.stop()

    def test_global_limit_is_released_when_setup_ends(self):
        server = self._server(max_pending=1, per_source=2)
        first = socket.create_connection(server.address, timeout=5)
        first.settimeout(0.25)
        excess = None
        replacement = None
        try:
            assert wait_until(lambda: server._setup_admission._total == 1)
            excess = socket.create_connection(server.address, timeout=5)
            excess.settimeout(2)
            assert wait_until(lambda: self._is_closed(excess), timeout=2)
            assert server._setup_admission._total == 1

            first.close()
            assert wait_until(lambda: server._setup_admission._total == 0)

            replacement = socket.create_connection(server.address, timeout=5)
            replacement.settimeout(0.25)
            assert wait_until(lambda: server._setup_admission._total == 1)
            assert not self._is_closed(replacement)
        finally:
            if excess is not None:
                excess.close()
            if replacement is not None:
                replacement.close()
            server.stop()

    def test_stop_closes_a_socket_still_in_handshake_setup(self):
        server = self._server(max_pending=1, per_source=1)
        peer = socket.create_connection(server.address, timeout=5)
        peer.settimeout(2)
        try:
            assert wait_until(lambda: server._setup_admission._total == 1)
            assert wait_until(lambda: len(server._pending_sockets) == 1)

            server.stop()

            assert wait_until(lambda: self._is_closed(peer), timeout=2)
            assert wait_until(lambda: server._setup_admission._total == 0)
            assert server._pending_sockets == set()
        finally:
            peer.close()
            server.stop()


class TestServerActiveAdmission:
    """Established sessions and their workers are capped after destination dial."""

    class _Tunnel:
        def __init__(self, fail_result=False):
            self.fail_result = fail_result
            self.results = []
            self.close_calls = 0

        def handshake(self):
            pass

        def wait_open(self, timeout):
            return 'destination.example', 443

        def open_result(self, status):
            if self.fail_result:
                raise OSError('client disappeared')
            self.results.append(status)

        def close(self):
            self.close_calls += 1

    class _Upstream:
        def __init__(self):
            self.timeout = None
            self.close_calls = 0

        def settimeout(self, timeout):
            self.timeout = timeout

        def close(self):
            self.close_calls += 1

    @staticmethod
    def _server(maximum, per_source):
        return fteproxy.relay.ServerListener(
            LOCAL, 0, object(), max_active=maximum,
            max_active_per_source=per_source)

    def _successful_dial(self, monkeypatch, server, addr, fail_result=False):
        tunnel = self._Tunnel(fail_result=fail_result)
        upstream = self._Upstream()
        monkeypatch.setattr(fteproxy, 'wrap_socket',
                            lambda raw, server_key=None: tunnel)
        monkeypatch.setattr(
            fteproxy.stream, 'connect',
            lambda host, port, rules, timeout:
                (fteproxy.stream.SUCCEEDED, upstream))
        return tunnel, upstream, server.serve(object(), addr)

    @pytest.mark.parametrize('maximum,per_source,occupied,attempted', [
        (1, 1, ('192.0.2.10', 10001), ('192.0.2.11', 10002)),
        (2, 1, ('192.0.2.10', 10001), ('192.0.2.10', 10002)),
    ])
    def test_capacity_refuses_after_dial_but_before_success(
            self, monkeypatch, maximum, per_source, occupied, attempted):
        server = self._server(maximum, per_source)
        held = server._active_admission.acquire(occupied)
        assert held is not None
        try:
            tunnel, upstream, connection = self._successful_dial(
                monkeypatch, server, attempted)

            assert connection is None
            assert tunnel.results == [fteproxy.stream.GENERAL_FAILURE]
            assert upstream.close_calls == 1
            assert upstream.timeout is None
            assert server._active_admission._total == 1
        finally:
            server._active_admission.release(held)

    def test_partial_worker_start_releases_the_active_slot_once(
            self, monkeypatch):
        server = self._server(1, 1)
        tunnel, upstream, connection = self._successful_dial(
            monkeypatch, server, ('192.0.2.10', 10001))
        assert server._active_admission._total == 1
        assert tunnel.results == [fteproxy.stream.SUCCEEDED]

        class _Worker:
            def __init__(self, *args, **kwargs):
                self.daemon = False

            def start(self):
                raise RuntimeError('thread capacity exhausted')

            def stop(self):
                pass

        monkeypatch.setattr(fteproxy.relay, 'worker', _Worker)

        with pytest.raises(RuntimeError, match='thread capacity exhausted'):
            connection.start()

        assert server._active_admission._total == 0
        assert tunnel.close_calls == 1
        assert upstream.close_calls == 1
        connection.close()
        assert server._active_admission._total == 0

    def test_listener_shutdown_releases_active_slots_idempotently(
            self, monkeypatch):
        server = self._server(1, 1)
        tunnel, upstream, connection = self._successful_dial(
            monkeypatch, server, ('192.0.2.10', 10001))
        server._running = True
        with server._connections_lock:
            server._connections.add(connection)

        server.stop()
        server.stop()
        connection.close()

        assert server._active_admission._total == 0
        assert tunnel.close_calls == 1
        assert upstream.close_calls == 1
        replacement = server._active_admission.acquire(
            ('192.0.2.11', 10002))
        assert replacement is not None
        server._active_admission.release(replacement)

    def test_failed_success_reply_releases_the_reserved_slot(
            self, monkeypatch):
        server = self._server(1, 1)

        tunnel, upstream, connection = self._successful_dial(
            monkeypatch, server, ('192.0.2.10', 10001), fail_result=True)

        assert connection is None
        assert server._active_admission._total == 0
        assert tunnel.close_calls == 1
        assert upstream.close_calls == 1


class TestClientAdmission:
    """Local SOCKS/forward setup work is bounded before a thread is made."""

    def test_global_and_per_source_limits_apply_to_client_listeners(self):
        _private, public = fteproxy.generate_server_key()
        listener = fteproxy.relay.SocksListener(
            LOCAL, 0, (LOCAL, 1), public, max_pending=2,
            max_pending_per_source=1)

        first = listener._admit((LOCAL, 10001))
        assert first is not None
        assert listener._admit((LOCAL, 10002)) is None

        second = listener._admit(('127.0.0.2', 10003))
        assert second is not None
        assert listener._admit(('127.0.0.3', 10004)) is None

        listener._release_admission(first)
        replacement = listener._admit((LOCAL, 10005))
        assert replacement is not None
        listener._release_admission(second)
        listener._release_admission(replacement)


class TestListenerLifecycle:

    def test_partial_connection_start_closes_and_forgets_everything(
            self, monkeypatch):
        made_workers = []

        class _Socket:
            def __init__(self):
                self.close_calls = 0

            def close(self):
                self.close_calls += 1

        class _Worker:
            def __init__(self, source, sink, on_finish=None):
                self.daemon = False
                self.started = False
                self.stopped = False
                made_workers.append(self)

            def start(self):
                if len(made_workers) == 2:
                    raise RuntimeError('cannot create another thread')
                self.started = True

            def stop(self):
                self.stopped = True

        monkeypatch.setattr(fteproxy.relay, 'worker', _Worker)
        sockets = (_Socket(), _Socket())
        tracked = set()
        connection = fteproxy.relay.Connection(
            sockets[0], sockets[1], on_close=tracked.discard)
        tracked.add(connection)

        with pytest.raises(RuntimeError, match='cannot create another thread'):
            connection.start()

        assert tracked == set()
        assert [item.started for item in made_workers] == [True, False]
        assert all(item.stopped for item in made_workers)
        assert [item.close_calls for item in sockets] == [1, 1]

        # Late worker completion or repeated cleanup must not close the sockets
        # or run the bookkeeping callback a second time.
        connection.close()
        assert [item.close_calls for item in sockets] == [1, 1]

    def test_a_connection_closed_during_shutdown_cannot_start_workers(
            self, monkeypatch):
        made_workers = []

        class _Socket:
            def close(self):
                pass

        class _Worker:
            def __init__(self, *args, **kwargs):
                made_workers.append(self)

        monkeypatch.setattr(fteproxy.relay, 'worker', _Worker)
        connection = fteproxy.relay.Connection(_Socket(), _Socket())

        connection.close()
        assert connection.start() is connection

        assert made_workers == []

    def test_shutdown_closes_a_just_prepared_connection_outside_the_lock(self):
        subject = fteproxy.relay.listener(LOCAL, 0)
        subject._running = False

        class _Connection:
            closed = False

            def close(inner_self):
                assert not subject._connections_lock.locked()
                inner_self.closed = True

        connection = _Connection()
        subject.serve = lambda conn, addr: connection

        subject._serve(object(), (LOCAL, 10001))

        assert connection.closed
        assert subject._connections == set()

    def test_stop_while_an_unbound_listener_starts_cannot_be_lost(self):
        entered_bind = threading.Event()
        finish_bind = threading.Event()

        class _Socket:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        sock = _Socket()
        subject = fteproxy.relay.listener(LOCAL, 0)

        def delayed_bind():
            entered_bind.set()
            assert finish_bind.wait(2)
            subject._sock = sock

        subject.bind = delayed_bind
        subject.start()
        try:
            assert entered_bind.wait(2)
            subject.stop()
        finally:
            finish_bind.set()
            subject.join(2)
            subject.stop()

        assert not subject.is_alive()
        assert not subject._running
        assert sock.closed

    def test_accept_failure_is_recorded_as_terminal(self):
        class _Socket:
            def __init__(self):
                self.closed = False

            def accept(self):
                raise OSError('descriptor exhausted')

            def close(self):
                self.closed = True

        sock = _Socket()
        subject = fteproxy.relay.listener(LOCAL, 0)
        subject._sock = sock
        subject._activated = True

        subject.run()

        assert subject.terminal_error == \
            'accept failed: descriptor exhausted'
        assert sock.closed
        assert not subject._running

    def test_setup_thread_start_failure_is_recorded_and_closes_socket(
            self, monkeypatch):
        class _ConnectionSocket:
            def __init__(self):
                self.closed = False

            def setsockopt(self, *args):
                pass

            def settimeout(self, timeout):
                pass

            def close(self):
                self.closed = True

        connection = _ConnectionSocket()

        class _ListenerSocket:
            def __init__(self):
                self.closed = False

            def accept(self):
                return connection, (LOCAL, 10001)

            def close(self):
                self.closed = True

        class _FailingThread:
            def __init__(self, *args, **kwargs):
                self.daemon = False

            def start(self):
                raise RuntimeError('thread capacity exhausted')

        class _Threading:
            Thread = _FailingThread

        sock = _ListenerSocket()
        subject = fteproxy.relay.listener(LOCAL, 0)
        subject._sock = sock
        subject._activated = True
        monkeypatch.setattr(fteproxy.relay, 'threading', _Threading)

        subject.run()

        assert subject.terminal_error == \
            'could not start connection worker: thread capacity exhausted'
        assert connection.closed
        assert sock.closed


class TestStartupCheck:
    """The client's ``--no-check`` counterpart: one short session."""

    def test_check_reports_the_negotiated_session(self, tunnel_factory):
        tunnel = tunnel_factory()
        listener = tunnel.forward((LOCAL, 1))
        assert listener.check() == ('http', 'hybrid')

    def test_check_fails_on_a_wrong_server_id(self, tunnel_factory):
        tunnel = tunnel_factory()
        _other_private, other_public = fteproxy.generate_server_key()
        listener = fteproxy.relay.ForwardListener(
            LOCAL, 0, tunnel.address, other_public, destination=(LOCAL, 1))
        previous = fteproxy.conf.getValue('runtime.fteproxy.handshake.timeout')
        fteproxy.conf.setValue('runtime.fteproxy.handshake.timeout', 1)
        try:
            with pytest.raises(fteproxy.HandshakeFailedException):
                listener.check()
        finally:
            fteproxy.conf.setValue('runtime.fteproxy.handshake.timeout',
                                   previous)


class TestConnectionBookkeeping:
    """A long-running listener must not hold every connection it ever saw."""

    def test_finished_connections_are_forgotten(self, echo, tunnel_factory):
        tunnel = tunnel_factory(
            rules=fteproxy.stream.AllowRules(['%s:%d' % (LOCAL, echo.port)]))
        listener = tunnel.forward((LOCAL, echo.port))
        for _ in range(5):
            sock = socket.create_connection(listener.address, timeout=15)
            sock.settimeout(15)
            try:
                sock.sendall(b'ping')
                assert sock.recv(4096) == b'ping'
            finally:
                sock.close()
        deadline = time.monotonic() + 15
        while listener._connections and time.monotonic() < deadline:
            time.sleep(0.1)
        assert listener._connections == set()


class TestSocketOwnership:
    """A setup failure closes every socket acquired before ownership moves."""

    @pytest.mark.parametrize('failure', ['setsockopt', 'wrap', 'settimeout'])
    def test_client_dial_failure_closes_the_raw_socket(
            self, monkeypatch, failure):
        class _Raw:
            closed = False

            def setsockopt(inner_self, *args):
                if failure == 'setsockopt':
                    raise RuntimeError('setsockopt failed')

            def shutdown(inner_self, _how):
                pass

            def close(inner_self):
                inner_self.closed = True

        class _Tunnel:
            def handshake(inner_self):
                pass

            def settimeout(inner_self, _timeout):
                if failure == 'settimeout':
                    raise RuntimeError('settimeout failed')

        raw = _Raw()
        monkeypatch.setattr(fteproxy.relay.socket, 'create_connection',
                            lambda *args, **kwargs: raw)

        def wrap(*args, **kwargs):
            if failure == 'wrap':
                raise RuntimeError('wrap failed')
            return _Tunnel()

        monkeypatch.setattr(fteproxy, 'wrap_socket', wrap)
        _private, public = fteproxy.generate_server_key()
        listener = fteproxy.relay.ForwardListener(
            LOCAL, 0, (LOCAL, 1), public, destination=(LOCAL, 2))

        with pytest.raises(RuntimeError, match='failed'):
            listener.dial_tunnel()

        assert raw.closed

    def test_server_timeout_failure_closes_tunnel_and_upstream(
            self, monkeypatch):
        class _Endpoint:
            def __init__(inner_self, fail_timeout=False):
                inner_self.closed = False
                inner_self.fail_timeout = fail_timeout

            def handshake(inner_self):
                pass

            def wait_open(inner_self, timeout=None):
                return 'example.test', 443

            def open_result(inner_self, status):
                pass

            def settimeout(inner_self, timeout):
                if inner_self.fail_timeout:
                    raise RuntimeError('settimeout failed')

            def shutdown(inner_self, _how):
                pass

            def close(inner_self):
                inner_self.closed = True

        tunnel = _Endpoint()
        upstream = _Endpoint(fail_timeout=True)
        monkeypatch.setattr(fteproxy, 'wrap_socket',
                            lambda *args, **kwargs: tunnel)
        monkeypatch.setattr(
            fteproxy.stream, 'connect',
            lambda *args, **kwargs: (fteproxy.stream.SUCCEEDED, upstream))
        private, _public = fteproxy.generate_server_key()
        listener = fteproxy.relay.ServerListener(LOCAL, 0, private)

        with pytest.raises(RuntimeError, match='settimeout failed'):
            listener.serve(object(), (LOCAL, 10001))

        assert tunnel.closed
        assert upstream.closed
