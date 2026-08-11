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


def _attempt_transfer(test_data):
    """Run a single end-to-end transfer through the proxy chain.

    Opens a fresh destination server on PROXY_PORT, connects to the
    fteproxy client, sends ``test_data`` and returns the bytes received on
    the destination side. Any socket error/timeout propagates so callers
    can retry.
    """
    received_data = b''
    dest_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dest_server.bind((BIND_IP, PROXY_PORT))
    dest_server.listen(1)
    dest_server.settimeout(DATA_TIMEOUT)

    client_conn = None
    proxy_conn = None
    try:
        client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_conn.connect((BIND_IP, CLIENT_PORT))
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


def transfer_through_proxy(test_data, attempts=3):
    """End-to-end transfer with retries to absorb proxy startup races.

    A freshly started proxy chain occasionally drops the very first
    connection while the FTE client/server handshake settles. Each attempt
    uses a brand new connection, so a retry still exercises a real transfer;
    the last attempt's bytes are returned for the caller to assert on.
    """
    received_data = b''
    for attempt in range(attempts):
        try:
            received_data = _attempt_transfer(test_data)
            if received_data == test_data:
                return received_data
        except (socket.timeout, OSError):
            received_data = b''
        if attempt < attempts - 1:
            time.sleep(1)
    return received_data


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
        yield proc
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    def test_key_file_data_transfer(self, fteproxy_client):
        """Data should flow end-to-end when both sides load a key from file."""
        test_data = b'Hello, key file!'
        received_data = b''

        dest_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        dest_server.bind((BIND_IP, KEYFILE_PROXY_PORT))
        dest_server.listen(1)
        dest_server.settimeout(DATA_TIMEOUT)

        try:
            client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_conn.connect((BIND_IP, KEYFILE_CLIENT_PORT))
            client_conn.settimeout(DATA_TIMEOUT)

            proxy_conn, _ = dest_server.accept()
            proxy_conn.settimeout(DATA_TIMEOUT)

            client_conn.sendall(test_data)

            while len(received_data) < len(test_data):
                chunk = proxy_conn.recv(1024)
                if not chunk:
                    break
                received_data += chunk

            assert received_data == test_data, \
                f"Data mismatch: {received_data} != {test_data}"
        finally:
            client_conn.close()
            proxy_conn.close()
            dest_server.close()
