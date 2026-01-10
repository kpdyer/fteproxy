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
    """Get the path to the fteproxy command."""
    # Try to find fteproxy in the bin directory
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    bin_path = os.path.join(base_dir, 'bin', 'fteproxy')
    if os.path.exists(bin_path):
        return [sys.executable, bin_path]
    # Fall back to module execution
    return [sys.executable, '-m', 'fteproxy.cli']


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
        received_data = b''
        
        # Create a "destination" server that will receive proxied data
        dest_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        dest_server.bind((BIND_IP, PROXY_PORT))
        dest_server.listen(1)
        dest_server.settimeout(DATA_TIMEOUT)
        
        try:
            # Connect to the fteproxy client
            client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_conn.connect((BIND_IP, CLIENT_PORT))
            client_conn.settimeout(DATA_TIMEOUT)
            
            # Accept the proxied connection
            proxy_conn, _ = dest_server.accept()
            proxy_conn.settimeout(DATA_TIMEOUT)
            
            # Send data through the proxy
            client_conn.sendall(test_data)
            
            # Receive data on the other side
            while len(received_data) < len(test_data):
                chunk = proxy_conn.recv(1024)
                if not chunk:
                    break
                received_data += chunk
            
            assert received_data == test_data, f"Data mismatch: {received_data} != {test_data}"
            
        finally:
            client_conn.close()
            proxy_conn.close()
            dest_server.close()

    def test_large_data_transfer(self, fteproxy_client):
        """Test transfer of larger data through the proxy."""
        test_data = random_bytes(64 * 1024)  # 64KB
        received_data = b''
        
        dest_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        dest_server.bind((BIND_IP, PROXY_PORT))
        dest_server.listen(1)
        dest_server.settimeout(DATA_TIMEOUT)
        
        try:
            client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_conn.connect((BIND_IP, CLIENT_PORT))
            client_conn.settimeout(DATA_TIMEOUT)
            
            proxy_conn, _ = dest_server.accept()
            proxy_conn.settimeout(DATA_TIMEOUT)
            
            # Send data in chunks
            sent = 0
            while sent < len(test_data):
                chunk_size = min(4096, len(test_data) - sent)
                client_conn.send(test_data[sent:sent + chunk_size])
                sent += chunk_size
            
            # Receive all data
            while len(received_data) < len(test_data):
                try:
                    chunk = proxy_conn.recv(4096)
                    if not chunk:
                        break
                    received_data += chunk
                except socket.timeout:
                    break
            
            assert len(received_data) == len(test_data), \
                f"Size mismatch: {len(received_data)} != {len(test_data)}"
            assert received_data == test_data, "Data content mismatch"
            
        finally:
            client_conn.close()
            proxy_conn.close()
            dest_server.close()

    def test_multiple_connections(self, fteproxy_client):
        """Test multiple sequential connections through the proxy."""
        for i in range(3):
            test_data = f'Connection {i}: {random_bytes(100).decode()}'.encode('utf-8')
            received_data = b''
            
            dest_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dest_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            dest_server.bind((BIND_IP, PROXY_PORT))
            dest_server.listen(1)
            dest_server.settimeout(DATA_TIMEOUT)
            
            try:
                client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_conn.connect((BIND_IP, CLIENT_PORT))
                client_conn.settimeout(DATA_TIMEOUT)
                
                proxy_conn, _ = dest_server.accept()
                proxy_conn.settimeout(DATA_TIMEOUT)
                
                client_conn.sendall(test_data)
                
                while len(received_data) < len(test_data):
                    chunk = proxy_conn.recv(1024)
                    if not chunk:
                        break
                    received_data += chunk
                
                assert received_data == test_data, f"Connection {i} failed"
                
            finally:
                client_conn.close()
                proxy_conn.close()
                dest_server.close()
            
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
