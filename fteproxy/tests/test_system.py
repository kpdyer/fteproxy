#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
System tests that spin up actual fteproxy client and server processes.

These tests verify end-to-end functionality by:
1. Starting a fteproxy server
2. Starting a fteproxy client
3. Sending data through the proxy chain
4. Verifying data integrity
"""

import os
import sys
import time
import socket
import signal
import subprocess
import random
import string

import pytest


# Test configuration
BIND_IP = '127.0.0.1'
CLIENT_PORT = 18079
SERVER_PORT = 18080
PROXY_PORT = 18081
STARTUP_TIMEOUT = 30
DATA_TIMEOUT = 30


def random_bytes(size):
    """Generate random bytes for testing."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode('utf-8')


def wait_for_port(host, port, timeout=STARTUP_TIMEOUT):
    """Wait for a port to become available."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((host, port))
            sock.close()
            return True
        except (socket.error, socket.timeout):
            time.sleep(0.5)
    return False


def get_fteproxy_cmd():
    """Get the command to run fteproxy."""
    # Use module execution - the canonical way to run fteproxy
    return [sys.executable, '-m', 'fteproxy']


def _attempt_transfer(test_data, client_port=CLIENT_PORT, proxy_port=PROXY_PORT):
    """Run a single end-to-end transfer through the proxy chain.

    Opens a fresh destination server on ``proxy_port``, connects to the
    fteproxy client on ``client_port``, sends ``test_data`` and returns the
    bytes received on the destination side. Any socket error/timeout
    propagates so callers can retry.
    """
    received_data = b''
    dest_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dest_server.bind((BIND_IP, proxy_port))
    dest_server.listen(1)
    dest_server.settimeout(DATA_TIMEOUT)

    client_conn = None
    proxy_conn = None
    try:
        client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_conn.connect((BIND_IP, client_port))
        client_conn.settimeout(DATA_TIMEOUT)

        proxy_conn, _ = dest_server.accept()
        proxy_conn.settimeout(DATA_TIMEOUT)

        # Send data in chunks so large payloads don't overflow send buffers.
        sent = 0
        while sent < len(test_data):
            chunk_size = min(4096, len(test_data) - sent)
            client_conn.sendall(test_data[sent:sent + chunk_size])
            sent += chunk_size

        while len(received_data) < len(test_data):
            chunk = proxy_conn.recv(4096)
            if not chunk:
                break
            received_data += chunk

        return received_data
    finally:
        for sock in (client_conn, proxy_conn, dest_server):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def transfer_through_proxy(test_data, attempts=3, client_port=CLIENT_PORT, proxy_port=PROXY_PORT):
    """End-to-end transfer with retries to absorb proxy startup races.

    A freshly started proxy chain occasionally drops the very first
    connection while the FTE client/server handshake settles. Each attempt
    uses a brand new connection, so a retry still exercises a real transfer;
    the last attempt's bytes are returned for the caller to assert on.
    """
    received_data = b''
    for attempt in range(attempts):
        try:
            received_data = _attempt_transfer(test_data, client_port=client_port, proxy_port=proxy_port)
            if received_data == test_data:
                return received_data
        except (socket.timeout, OSError):
            received_data = b''
        if attempt < attempts - 1:
            time.sleep(1)
    return received_data


def client_wire_bytes(payload):
    """Capture what a negotiating fteproxy client sends for ``payload``.

    Returns ``(negotiation, data)``: the negotiation record and the first data
    record, built in-process with the default key and record-layer mode, which
    are what a server process started without ``--key`` or
    ``--record-layer-mode`` runs with.
    """
    import fteproxy
    import fteproxy.conf
    import fteproxy.defs

    class Capture:
        def __init__(self):
            self.sent = []

        def send(self, data):
            self.sent.append(data)
            return len(data)

        def sendall(self, data):
            self.sent.append(data)

    mode_key = 'runtime.fteproxy.record_layer.mode'
    prev_mode = fteproxy.conf.getValue(mode_key)
    fteproxy.conf.setValue(mode_key, 'hybrid')
    try:
        fteproxy.defs.load_definitions()
        up = fteproxy.conf.getValue('runtime.state.upstream_language')
        down = fteproxy.conf.getValue('runtime.state.downstream_language')
        sock = Capture()
        client = fteproxy.wrap_socket(
            sock,
            outgoing_regex=fteproxy.defs.getRegex(up),
            outgoing_length=fteproxy.defs.getLength(up),
            incoming_regex=fteproxy.defs.getRegex(down),
            incoming_length=fteproxy.defs.getLength(down))
        client.send(payload)
    finally:
        fteproxy.conf.setValue(mode_key, prev_mode)
    negotiation, data = sock.sent
    return negotiation, data


def send_raw_to_server(wire, server_port=SERVER_PORT, proxy_port=PROXY_PORT):
    """Send ``wire`` verbatim to the fteproxy server port, half-close, and
    return every byte the destination on ``proxy_port`` received before EOF.

    Bypasses the fteproxy client entirely, so the caller controls the exact
    record sequence the server sees.
    """
    received = b''
    dest_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dest_server.bind((BIND_IP, proxy_port))
    dest_server.listen(1)
    dest_server.settimeout(DATA_TIMEOUT)

    raw = None
    proxy_conn = None
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.connect((BIND_IP, server_port))
        raw.settimeout(DATA_TIMEOUT)

        # The server dials the destination as soon as it accepts.
        proxy_conn, _ = dest_server.accept()
        proxy_conn.settimeout(DATA_TIMEOUT)

        raw.sendall(wire)
        # EOF on the covert side: the server relays whatever decoded, then
        # closes the destination side, which ends the loop below.
        raw.shutdown(socket.SHUT_WR)

        while True:
            chunk = proxy_conn.recv(4096)
            if not chunk:
                break
            received += chunk
        return received
    finally:
        for sock in (raw, proxy_conn, dest_server):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


class TestSystemEndToEnd:
    """End-to-end system tests with actual client/server processes."""

    @pytest.fixture
    def fteproxy_server(self):
        """Start an fteproxy server process."""
        cmd = get_fteproxy_cmd() + [
            '--mode', 'server',
            '--quiet',
            '--server_ip', BIND_IP,
            '--server_port', str(SERVER_PORT),
            '--proxy_ip', BIND_IP,
            '--proxy_port', str(PROXY_PORT),
        ]
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        # Wait for server to start
        if not wait_for_port(BIND_IP, SERVER_PORT):
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=5)
            pytest.fail(f"Server failed to start. stdout: {stdout}, stderr: {stderr}")
        # Give the listener a moment to settle after the readiness probe.
        time.sleep(1)

        yield proc
        
        # Cleanup
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    @pytest.fixture
    def fteproxy_client(self, fteproxy_server):
        """Start an fteproxy client process (requires server)."""
        cmd = get_fteproxy_cmd() + [
            '--mode', 'client',
            '--quiet',
            '--client_ip', BIND_IP,
            '--client_port', str(CLIENT_PORT),
            '--server_ip', BIND_IP,
            '--server_port', str(SERVER_PORT),
        ]
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        # Wait for client to start
        if not wait_for_port(BIND_IP, CLIENT_PORT):
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=5)
            pytest.fail(f"Client failed to start. stdout: {stdout}, stderr: {stderr}")
        # Give the listener a moment to settle after the readiness probe.
        time.sleep(1)

        yield proc
        
        # Cleanup
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    def test_basic_data_transfer(self, fteproxy_client):
        """Test basic data transfer through the proxy."""
        test_data = b'Hello, fteproxy!'
        received_data = transfer_through_proxy(test_data)
        assert received_data == test_data, f"Data mismatch: {received_data!r} != {test_data!r}"

    def test_large_data_transfer(self, fteproxy_client):
        """Test transfer of larger data through the proxy."""
        test_data = random_bytes(64 * 1024)  # 64KB
        received_data = transfer_through_proxy(test_data)
        assert len(received_data) == len(test_data), \
            f"Size mismatch: {len(received_data)} != {len(test_data)}"
        assert received_data == test_data, "Data content mismatch"

    def test_multiple_connections(self, fteproxy_client):
        """Test multiple sequential connections through the proxy."""
        for i in range(3):
            test_data = f'Connection {i}: {random_bytes(100).decode()}'.encode('utf-8')
            received_data = transfer_through_proxy(test_data)
            assert received_data == test_data, f"Connection {i} failed"
            time.sleep(0.5)  # Brief pause between connections

    def test_duplicated_negotiation_record_delivers_nothing(self, fteproxy_server):
        """A replayed negotiation record must not reach the destination.

        Sends captured client wire bytes straight to the server port. The
        control stream ``[nego][data0]`` delivers the payload. With the
        negotiation record duplicated, ``[nego][nego][data0]``, the server
        accepts the first cell and the duplicate is then out of its stream
        position, so the destination must see no bytes at all before EOF: not
        the cell's plaintext (which a server that restarted its sequence
        counter after negotiation relayed as application data) and not
        ``data0``.
        """
        payload = b'Hello, fteproxy!'
        negotiation, data = client_wire_bytes(payload)

        # Control first; it also absorbs a still-settling server, as
        # transfer_through_proxy does.
        control = b''
        for attempt in range(3):
            try:
                control = send_raw_to_server(negotiation + data)
            except (socket.timeout, OSError):
                control = b''
            if control == payload:
                break
            time.sleep(1)
        assert control == payload, f"control stream failed: {control!r}"

        delivered = send_raw_to_server(negotiation + negotiation + data)
        assert delivered == b'', \
            f"duplicated negotiation record leaked {delivered!r} to the destination"


class TestCLI:
    """Tests for the fteproxy CLI."""

    def test_version(self):
        """Test --version flag."""
        cmd = get_fteproxy_cmd() + ['--version']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0
        # Version should be in the output
        assert result.stdout.strip() or result.stderr.strip()

    def test_help(self):
        """Test --help flag."""
        cmd = get_fteproxy_cmd() + ['--help']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0
        assert '--mode' in result.stdout
        assert 'client' in result.stdout
        assert 'server' in result.stdout

    def test_invalid_mode(self):
        """Test that invalid mode is rejected."""
        cmd = get_fteproxy_cmd() + ['--mode', 'invalid']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert result.returncode != 0

    def test_key_file_in_help(self):
        """Test that --key-file appears in the help output."""
        cmd = get_fteproxy_cmd() + ['--help']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0
        assert '--key-file' in result.stdout

    def test_key_file_missing(self, tmp_path):
        """Test that a nonexistent key file is rejected."""
        missing = tmp_path / 'does-not-exist.key'
        cmd = get_fteproxy_cmd() + ['--mode', 'server', '--key-file', str(missing)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert result.returncode != 0

    def test_key_file_invalid_length(self, tmp_path):
        """Test that a key file with the wrong length is rejected."""
        key_file = tmp_path / 'short.key'
        key_file.write_text('abcdef')
        cmd = get_fteproxy_cmd() + ['--mode', 'server', '--key-file', str(key_file)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert result.returncode != 0

    def test_key_file_invalid_characters(self, tmp_path):
        """Test that a key file with non-hex characters is rejected."""
        key_file = tmp_path / 'nonhex.key'
        key_file.write_text('z' * 64)
        cmd = get_fteproxy_cmd() + ['--mode', 'server', '--key-file', str(key_file)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert result.returncode != 0

    def test_key_and_key_file_mutually_exclusive(self, tmp_path):
        """Test that --key and --key-file cannot be used together."""
        key_file = tmp_path / 'good.key'
        key_file.write_text('a' * 64)
        cmd = get_fteproxy_cmd() + [
            '--mode', 'server',
            '--key', 'a' * 64,
            '--key-file', str(key_file),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert result.returncode != 0
        assert '--key-file' in result.stderr and '--key' in result.stderr


# A non-default 64-hex-character key, so a successful transfer proves both the
# server and the client actually loaded the key from the shared key file.
KEYFILE_TEST_KEY = '0123456789abcdef' * 4
KEYFILE_CLIENT_PORT = 18179
KEYFILE_SERVER_PORT = 18180
KEYFILE_PROXY_PORT = 18181


class TestKeyFileEndToEnd:
    """End-to-end test that server and client interoperate via a key file."""

    @pytest.fixture
    def key_file(self, tmp_path):
        """Write a shared key file used by both the server and the client."""
        path = tmp_path / 'fteproxy.key'
        path.write_text(KEYFILE_TEST_KEY + '\n')
        return str(path)

    @pytest.fixture
    def fteproxy_server(self, key_file):
        """Start an fteproxy server that reads its key from a file."""
        cmd = get_fteproxy_cmd() + [
            '--mode', 'server',
            '--quiet',
            '--server_ip', BIND_IP,
            '--server_port', str(KEYFILE_SERVER_PORT),
            '--proxy_ip', BIND_IP,
            '--proxy_port', str(KEYFILE_PROXY_PORT),
            '--key-file', key_file,
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not wait_for_port(BIND_IP, KEYFILE_SERVER_PORT):
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=5)
            pytest.fail(f"Server failed to start. stdout: {stdout}, stderr: {stderr}")
        # Give the listener a moment to settle after the readiness probe.
        time.sleep(1)
        yield proc
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    @pytest.fixture
    def fteproxy_client(self, fteproxy_server, key_file):
        """Start an fteproxy client that reads the same key from a file."""
        cmd = get_fteproxy_cmd() + [
            '--mode', 'client',
            '--quiet',
            '--client_ip', BIND_IP,
            '--client_port', str(KEYFILE_CLIENT_PORT),
            '--server_ip', BIND_IP,
            '--server_port', str(KEYFILE_SERVER_PORT),
            '--key-file', key_file,
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not wait_for_port(BIND_IP, KEYFILE_CLIENT_PORT):
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=5)
            pytest.fail(f"Client failed to start. stdout: {stdout}, stderr: {stderr}")
        # Give the listener a moment to settle after the readiness probe.
        time.sleep(1)
        yield proc
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    def test_key_file_data_transfer(self, fteproxy_client):
        """Data should flow end-to-end when both sides load a key from file."""
        test_data = b'Hello, key file!'
        received_data = transfer_through_proxy(
            test_data,
            client_port=KEYFILE_CLIENT_PORT,
            proxy_port=KEYFILE_PROXY_PORT,
        )
        assert received_data == test_data, \
            f"Data mismatch: {received_data!r} != {test_data!r}"
