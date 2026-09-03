#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""System tests that run real ``fteproxy`` processes.

These are the plan's section 1 transcript, executed: a server that generates a
key on first start and writes a connection string, a client that finds it and
opens a SOCKS5 listener or a forwarded port, and a transfer through the
result.

The ports here are fixed, so no two sessions of this file may run at once.
"""

import os
import random
import socket
import string
import subprocess
import sys
import threading
import time

import pytest

import fteproxy
import fteproxy.config
import fteproxy.stream


BIND_IP = '127.0.0.1'
SERVER_PORT = 18080
SOCKS_PORT = 18079
FORWARD_PORT = 18078
STARTUP_TIMEOUT = 30
DATA_TIMEOUT = 30


def random_bytes(size):
    """Generate random bytes for testing."""
    return ''.join(random.choices(string.ascii_letters + string.digits,
                                  k=size)).encode('utf-8')


def wait_for_port(host, port, timeout=STARTUP_TIMEOUT):
    """Wait for a port to accept connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((host, port))
            sock.close()
            return True
        except (OSError, socket.timeout):
            time.sleep(0.25)
    return False


def get_fteproxy_cmd():
    """The command that runs fteproxy: module execution, the canonical way."""
    return [sys.executable, '-m', 'fteproxy']


def run_cli(args, timeout=60, env=None):
    return subprocess.run(get_fteproxy_cmd() + args, capture_output=True,
                          text=True, timeout=timeout, env=env)


def start(args, env=None):
    return subprocess.Popen(get_fteproxy_cmd() + args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env)


def terminate(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


class EchoDestination:
    """A destination the tunnel can reach, echoing whatever it is sent."""

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((BIND_IP, 0))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._running = True
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
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

    @staticmethod
    def _serve(conn):
        conn.settimeout(DATA_TIMEOUT)
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._running = False


def transfer(address, payload):
    """Send ``payload`` through ``address`` and read the echo back."""
    sock = socket.create_connection(address, timeout=DATA_TIMEOUT)
    sock.settimeout(DATA_TIMEOUT)
    try:
        sock.sendall(payload)
        received = b''
        while len(received) < len(payload):
            chunk = sock.recv(65536)
            if not chunk:
                break
            received += chunk
        return received
    finally:
        sock.close()


def socks_connect(port, host, dest_port):
    """A SOCKS5 CONNECT by hand; returns ``(socket, reply status)``."""
    sock = socket.create_connection((BIND_IP, port), timeout=DATA_TIMEOUT)
    sock.settimeout(DATA_TIMEOUT)
    sock.sendall(b'\x05\x01\x00')
    assert sock.recv(2) == b'\x05\x00'
    sock.sendall(b'\x05\x01\x00'
                 + fteproxy.stream.encode_address(host, dest_port))
    head = sock.recv(4)
    width = {0x01: 4, 0x04: 16}.get(head[3]) or sock.recv(1)[0]
    sock.recv(width + 2)
    return sock, head[1]


# --------------------------------------------------------------------------- #
# Fixtures: the transcript from section 1 of the plan
# --------------------------------------------------------------------------- #

@pytest.fixture
def destination():
    echo = EchoDestination()
    yield echo
    echo.stop()


@pytest.fixture
def state_dir(tmp_path):
    return str(tmp_path / 'state')


@pytest.fixture
def server(destination, state_dir):
    """``fteproxy server``: makes a key on first start, writes the string."""
    proc = start([
        'server',
        '--listen', '%s:%d' % (BIND_IP, SERVER_PORT),
        '--advertise', '%s:%d' % (BIND_IP, SERVER_PORT),
        '--allow', '%s:%d' % (BIND_IP, destination.port),
        '--state-dir', state_dir,
    ])
    if not wait_for_port(BIND_IP, SERVER_PORT):
        terminate(proc)
        stdout, stderr = proc.communicate(timeout=5)
        pytest.fail('server failed to start. stdout: %s stderr: %s'
                    % (stdout, stderr))
    yield proc
    terminate(proc)


@pytest.fixture
def socks_client(server, state_dir):
    """``fteproxy client`` with no URI: it finds connection.txt."""
    proc = start(['client', '-D', '%s:%d' % (BIND_IP, SOCKS_PORT),
                  '--state-dir', state_dir])
    if not wait_for_port(BIND_IP, SOCKS_PORT):
        terminate(proc)
        stdout, stderr = proc.communicate(timeout=5)
        pytest.fail('client failed to start. stdout: %s stderr: %s'
                    % (stdout, stderr))
    yield proc
    terminate(proc)


class TestServerStartup:

    def test_the_first_start_writes_a_key_and_a_connection_string(
            self, server, state_dir):
        assert os.path.exists(fteproxy.config.server_key_path(state_dir))
        text = fteproxy.config.read_connection_string(state_dir)
        uri = fteproxy.config.ConnectionString.parse(text)
        assert uri.address == (BIND_IP, SERVER_PORT)
        private = fteproxy.config.load_server_key(state_dir)
        assert fteproxy.server_id(private) == uri.server_id

    def test_a_restart_keeps_the_same_identity(self, server, state_dir,
                                               destination):
        first = fteproxy.config.read_connection_string(state_dir)
        terminate(server)
        proc = start([
            'server', '--listen', '%s:%d' % (BIND_IP, SERVER_PORT),
            '--advertise', '%s:%d' % (BIND_IP, SERVER_PORT),
            '--allow', '%s:%d' % (BIND_IP, destination.port),
            '--state-dir', state_dir])
        try:
            assert wait_for_port(BIND_IP, SERVER_PORT)
            assert fteproxy.config.read_connection_string(state_dir) == first
        finally:
            terminate(proc)


class TestEndToEnd:

    def test_socks_transfer(self, socks_client, destination):
        sock, status = socks_connect(SOCKS_PORT, BIND_IP, destination.port)
        try:
            assert status == fteproxy.stream.SUCCEEDED
            payload = b'Hello, fteproxy!'
            sock.sendall(payload)
            assert sock.recv(4096) == payload
        finally:
            sock.close()

    def test_socks_large_transfer(self, socks_client, destination):
        payload = random_bytes(64 * 1024)
        sock, status = socks_connect(SOCKS_PORT, BIND_IP, destination.port)
        try:
            assert status == fteproxy.stream.SUCCEEDED
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

    def test_several_socks_connections(self, socks_client, destination):
        for index in range(3):
            payload = ('connection %d: ' % index).encode() + random_bytes(100)
            sock, status = socks_connect(SOCKS_PORT, BIND_IP, destination.port)
            try:
                assert status == fteproxy.stream.SUCCEEDED
                sock.sendall(payload)
                received = b''
                while len(received) < len(payload):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    received += chunk
                assert received == payload
            finally:
                sock.close()

    def test_the_allow_rules_are_enforced(self, socks_client, destination):
        """A destination outside --allow comes back as SOCKS5's 0x02."""
        sock, status = socks_connect(SOCKS_PORT, BIND_IP, destination.port + 1)
        sock.close()
        assert status == fteproxy.stream.NOT_ALLOWED

    def test_forward_transfer(self, server, state_dir, destination):
        """The old fixed-destination topology, spelled -L."""
        proc = start(['client', '-L', '%s:%d:%s:%d'
                      % (BIND_IP, FORWARD_PORT, BIND_IP, destination.port),
                      '--state-dir', state_dir])
        try:
            assert wait_for_port(BIND_IP, FORWARD_PORT)
            payload = random_bytes(8 * 1024)
            assert transfer((BIND_IP, FORWARD_PORT), payload) == payload
        finally:
            terminate(proc)

    def test_the_uri_can_come_from_the_environment(self, server, state_dir,
                                                   destination):
        env = dict(os.environ)
        env['FTEPROXY_URI'] = fteproxy.config.read_connection_string(state_dir)
        proc = start(['client', '-L', '%s:%d:%s:%d'
                      % (BIND_IP, FORWARD_PORT, BIND_IP, destination.port),
                      '--state-dir', state_dir + '-empty'], env=env)
        try:
            assert wait_for_port(BIND_IP, FORWARD_PORT)
            assert transfer((BIND_IP, FORWARD_PORT),
                            b'from the environment') == b'from the environment'
        finally:
            terminate(proc)

    def test_format_mode_end_to_end(self, server, state_dir, destination):
        """The client picks the record-layer mode; the server follows."""
        proc = start(['client', '--mode', 'format',
                      '-L', '%s:%d:%s:%d'
                      % (BIND_IP, FORWARD_PORT, BIND_IP, destination.port),
                      '--state-dir', state_dir])
        try:
            assert wait_for_port(BIND_IP, FORWARD_PORT)
            payload = b'every byte in the format' * 8
            assert transfer((BIND_IP, FORWARD_PORT), payload) == payload
        finally:
            terminate(proc)

    def test_a_non_default_format_end_to_end(self, server, state_dir,
                                             destination):
        """The server is told no format; it learns it from the first record."""
        proc = start(['client', '--format', 'words',
                      '-L', '%s:%d:%s:%d'
                      % (BIND_IP, FORWARD_PORT, BIND_IP, destination.port),
                      '--state-dir', state_dir])
        try:
            assert wait_for_port(BIND_IP, FORWARD_PORT)
            payload = b'traffic that looks like words'
            assert transfer((BIND_IP, FORWARD_PORT), payload) == payload
        finally:
            terminate(proc)


class TestCLI:
    """The command line as a process: statuses, output streams, old flags."""

    def test_version(self):
        result = run_cli(['--version'], timeout=30)
        assert result.returncode == 0
        assert fteproxy.__version__ in result.stdout

    def test_help_lists_the_subcommands(self):
        result = run_cli(['--help'], timeout=30)
        assert result.returncode == 0
        for name in ('server', 'client', 'keygen', 'formats'):
            assert name in result.stdout

    def test_no_arguments_prints_usage_and_exits_2(self):
        result = run_cli([], timeout=30)
        assert result.returncode == 2
        assert 'usage:' in result.stderr
        assert 'Traceback' not in result.stderr

    def test_formats_goes_to_stdout(self):
        result = run_cli(['formats'], timeout=60)
        assert result.returncode == 0
        assert 'manual-http' in result.stdout
        assert '(default)' in result.stdout

    def test_keygen_prints_the_connection_string(self, tmp_path):
        result = run_cli(['keygen', '--state-dir', str(tmp_path / 'state')],
                         timeout=30)
        assert result.returncode == 0
        assert result.stdout.strip().startswith('fte://')

    @pytest.mark.parametrize('flag', [
        '--mode', '--key', '--key-file', '--server_ip', '--proxy_port',
        '--upstream-format', '--record-layer-mode', '--stop', '--quiet',
    ])
    def test_removed_flags_point_at_the_upgrade_notes(self, flag):
        result = run_cli([flag, 'value'], timeout=30)
        assert result.returncode == 2
        assert flag in result.stderr
        assert 'Upgrading to 1.0.0' in result.stderr

    def test_an_unknown_format_exits_1(self, tmp_path):
        _private, public = fteproxy.generate_server_key()
        uri = fteproxy.config.ConnectionString(public, BIND_IP, 1)
        result = run_cli(['client', uri.format(), '--format', 'no-such-format',
                          '--no-check', '--state-dir', str(tmp_path)],
                         timeout=60)
        assert result.returncode == 1
        assert 'no-such-format' in result.stderr

    def test_a_client_with_nowhere_to_connect_exits_1(self, tmp_path):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind((BIND_IP, 0))
        port = probe.getsockname()[1]
        probe.close()
        _private, public = fteproxy.generate_server_key()
        uri = fteproxy.config.ConnectionString(public, BIND_IP, port)
        result = run_cli(['client', uri.format(),
                          '--state-dir', str(tmp_path / 'state')], timeout=60)
        assert result.returncode == 1
        assert 'checking %s:%d' % (BIND_IP, port) in result.stderr

    def test_no_connection_string_anywhere_exits_2(self, tmp_path):
        env = dict(os.environ)
        env.pop('FTEPROXY_URI', None)
        result = run_cli(['client', '--state-dir', str(tmp_path / 'nothing')],
                         timeout=30, env=env)
        assert result.returncode == 2
        assert 'FTEPROXY_URI' in result.stderr
        assert 'connection.txt' in result.stderr


# --------------------------------------------------------------------------- #
# The library API, without the command line
# --------------------------------------------------------------------------- #

class TestLibraryEndToEnd:
    """The same topology built with the library API.

    The command line above is one way to reach it; a program embedding
    fteproxy is the other, and both have to work.
    """

    @pytest.fixture
    def stack(self):
        import fteproxy.relay
        from fteproxy.tests.test_relay import EchoServer

        echo = EchoServer()
        echo.start()

        private, public = fteproxy.generate_server_key()
        rules = fteproxy.stream.AllowRules(['%s:%d' % (BIND_IP, echo.port)])
        server = fteproxy.relay.ServerListener(BIND_IP, 0, private, rules=rules)
        server.bind()
        server.daemon = True
        server.start()

        listeners = [server]

        def add(listener):
            listener.bind()
            listener.daemon = True
            listener.start()
            listeners.append(listener)
            return listener

        forward = add(fteproxy.relay.ForwardListener(
            BIND_IP, 0, server.address, public,
            destination=(BIND_IP, echo.port)))
        socks_listener = add(fteproxy.relay.SocksListener(
            BIND_IP, 0, server.address, public))

        yield {'echo': echo, 'forward': forward, 'socks': socks_listener,
               'server': server}

        for listener in listeners:
            listener.stop()
        echo.stop()

    def test_forward_transfer(self, stack):
        payload = random_bytes(64 * 1024)
        assert transfer(stack['forward'].address, payload) == payload

    def test_socks_transfer(self, stack):
        from fteproxy.tests.test_relay import socks_connect as connect

        payload = random_bytes(64 * 1024)
        sock, status = connect(stack['socks'].address[1], BIND_IP,
                               stack['echo'].port)
        try:
            assert status == fteproxy.stream.SUCCEEDED
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

    def test_socks_refuses_a_destination_outside_the_rules(self, stack):
        from fteproxy.tests.test_relay import socks_connect as connect

        sock, status = connect(stack['socks'].address[1], BIND_IP,
                               stack['echo'].port + 1)
        sock.close()
        assert status == fteproxy.stream.NOT_ALLOWED
