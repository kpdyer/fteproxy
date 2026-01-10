#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for Python 3 compatibility.
"""

import sys
import io
import socket
import contextlib

import pytest

import fteproxy
import fteproxy.conf
import fteproxy.defs
import fteproxy.network_io


class TestPython3Compatibility:
    """Test Python 3 specific functionality."""

    def test_python_version(self):
        """Ensure we're running Python 3.8+"""
        assert sys.version_info.major >= 3
        assert sys.version_info.minor >= 8

    def test_bytes_key_config(self):
        """Test that the encryption key is properly stored as bytes."""
        key = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_bytes_hex_conversion(self):
        """Test bytes to hex and back conversion (Python 3 style)."""
        original = b'\xff' * 16 + b'\x00' * 16
        hex_str = original.hex()
        assert isinstance(hex_str, str)
        assert len(hex_str) == 64
        
        restored = bytes.fromhex(hex_str)
        assert original == restored

    def test_string_rjust(self):
        """Test that string rjust works correctly."""
        test_str = "test"
        padded = test_str.rjust(10, '0')
        assert len(padded) == 10
        assert padded == "000000test"

    def test_negotiate_cell_bytes_handling(self):
        """Test NegotiateCell bytes operations."""
        cell = fteproxy.NegotiateCell()
        cell.setDefFile("20131224")
        cell.setLanguage("manual-http")
        
        cell_bytes = cell.toBytes()
        assert len(cell_bytes) == fteproxy.NegotiateCell._CELL_SIZE
        
        # Verify padding
        padding_len = fteproxy.NegotiateCell._PADDING_LEN
        padding_char = fteproxy.NegotiateCell._PADDING_CHAR
        assert cell_bytes[:padding_len] == padding_char * padding_len

    def test_unicode_handling(self):
        """Test that unicode strings work correctly."""
        test_str = "Hello, 世界! 🌍"
        encoded = test_str.encode('utf-8')
        assert isinstance(encoded, bytes)
        
        decoded = encoded.decode('utf-8')
        assert test_str == decoded

    def test_dict_keys_iteration(self):
        """Test that dict.keys() returns a view that can be iterated."""
        definitions = fteproxy.defs.load_definitions()
        keys = definitions.keys()
        
        # In Python 3, .keys() returns a view, not a list
        key_list = list(keys)
        assert len(key_list) > 0
        
        # Should be able to iterate multiple times
        for key in definitions.keys():
            assert isinstance(key, str)
            break

    def test_print_function(self):
        """Test that print is a function (not a statement)."""
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            print("test output")
        
        output = f.getvalue()
        assert output.strip() == "test output"


class TestNetworkIOBytes:
    """Test that network I/O uses bytes correctly."""

    def test_recvall_returns_bytes(self):
        """Test that recvall_from_socket returns bytes."""
        # Create a socket pair for testing
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('127.0.0.1', 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]
        
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(('127.0.0.1', port))
        
        conn, _ = server_sock.accept()
        
        try:
            # Send some data
            test_data = b'Hello, Python 3!'
            client_sock.sendall(test_data)
            
            # Receive using our function
            is_alive, received = fteproxy.network_io.recvall_from_socket(conn, select_timeout=1.0)
            
            assert is_alive
            assert isinstance(received, bytes)
            assert received == test_data
        finally:
            client_sock.close()
            conn.close()
            server_sock.close()


class TestWrapSocket:
    """Test fteproxy.wrap_socket functionality."""

    def test_wrap_socket_no_negotiate(self):
        """Test wrap_socket with negotiate=False (fixes issue #175)."""
        import threading
        
        client_server_regex = '^(0|1)+$'
        server_client_regex = '^(A|B)+$'
        test_data = b'Hello, world!'
        received_data = []
        
        def server_thread(port):
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock = fteproxy.wrap_socket(server_sock,
                outgoing_regex=server_client_regex,
                outgoing_fixed_slice=256,
                incoming_regex=client_server_regex,
                incoming_fixed_slice=256,
                negotiate=False)
            server_sock.bind(('127.0.0.1', port))
            server_sock.listen(1)
            
            conn, addr = server_sock.accept()
            conn.settimeout(5)
            try:
                data = conn.recv(1024)
                received_data.append(data)
                conn.sendall(data)  # Echo back
            finally:
                conn.close()
                server_sock.close()
        
        # Find an available port
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_sock.bind(('127.0.0.1', 0))
        port = temp_sock.getsockname()[1]
        temp_sock.close()
        
        # Start server in background
        server = threading.Thread(target=server_thread, args=(port,))
        server.start()
        
        import time
        time.sleep(0.5)  # Give server time to start
        
        # Client connects and sends data
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock = fteproxy.wrap_socket(client_sock,
            outgoing_regex=client_server_regex,
            outgoing_fixed_slice=256,
            incoming_regex=server_client_regex,
            incoming_fixed_slice=256,
            negotiate=False)
        
        try:
            client_sock.connect(('127.0.0.1', port))
            client_sock.settimeout(5)
            client_sock.sendall(test_data)
            echo_data = client_sock.recv(1024)
        finally:
            client_sock.close()
        
        server.join(timeout=5)
        
        # Verify data was received correctly
        assert len(received_data) == 1
        assert received_data[0] == test_data
        assert echo_data == test_data
