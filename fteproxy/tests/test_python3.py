#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for Python 3 compatibility.
"""

import sys
import io
import socket
import contextlib
import threading
import time

import pytest

import fteproxy
from fteproxy.tests import conftest
import fteproxy.conf
import fteproxy.defs
import fteproxy.network_io


class TestPython3Compatibility:
    """Test Python 3 specific functionality."""

    def test_python_version(self):
        """Ensure we're running Python 3.10+"""
        assert sys.version_info >= (3, 10)

    def test_bytes_key_config(self):
        """Test that the encryption key is properly stored as bytes."""
        key = conftest.TEST_KEY
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

    def test_client_hello_bytes_handling(self):
        """The client hello encodes to bytes and decodes back unchanged."""
        import fteproxy.handshake as hs

        hello = hs.ClientHello(mode='hybrid', defs=20131224,
                               format='manual-http',
                               client_public=bytes(range(32)), epoch=490000)
        raw = hello.encode()
        assert isinstance(raw, bytes)
        back = hs.ClientHello.decode(raw)
        assert back.format == 'manual-http'
        assert back.defs == 20131224
        assert back.mode == 'hybrid'
        assert back.client_public == bytes(range(32))
        assert back.epoch == 490000

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


class TestCipherCaching:
    """The DFA is cached; the keyed cipher is not."""

    def test_regex_format_is_cached(self):
        """``fte.RegexFormat`` compiles a DFA and depends only on the pattern
        and the length, so one instance serves every connection."""
        a = fteproxy._regex_format('^[a-z]+$', 64)
        assert fteproxy._regex_format('^[a-z]+$', 64) is a
        assert fteproxy._regex_format('^[a-z]+$', 96) is not a

    def test_make_cipher_is_per_session(self):
        """Every connection derives its own header keys, so caching the keyed
        cipher would add an entry per connection and never hit."""
        key = bytes(range(32))
        a = fteproxy._make_cipher('^[a-z]+$', 64, key)
        b = fteproxy._make_cipher('^[a-z]+$', 64, key)
        assert a is not b
        # ... but they share the expensive half.
        assert a.output_format is b.output_format

    def test_cover_cipher_is_cached(self):
        """K_cover is the same for every connection to a given server, and the
        first-record scan builds several per connection."""
        key = bytes(range(32))
        a = fteproxy._cover_cipher('^[a-z]+$', 64, key)
        assert fteproxy._cover_cipher('^[a-z]+$', 64, key) is a


class TestWrapSocket:
    """End-to-end use of the 0.4 wrap_socket."""

    @staticmethod
    def _echo_server(port, private, received, ready):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock = fteproxy.wrap_socket(sock, server_key=private)
        sock.bind(('127.0.0.1', port))
        sock.listen(1)
        ready.set()
        conn, _ = sock.accept()
        conn.settimeout(10)
        try:
            buf = b''
            while True:
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    break
                buf += data
                if buf == received['expected']:
                    break
            received['data'] = buf
            conn.sendall(buf)
            # Give the client time to drain before the socket goes away.
            time.sleep(0.3)
        finally:
            conn.close()
            sock.close()

    def _run(self, payload, mode, format='manual-http'):
        private, public = fteproxy.generate_server_key()
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()

        received = {'expected': payload}
        ready = threading.Event()
        server = threading.Thread(target=self._echo_server,
                                  args=(port, private, received, ready))
        server.start()
        assert ready.wait(5)

        client = fteproxy.wrap_socket(socket.socket(), server_id=public,
                                      format=format, mode=mode)
        try:
            client.connect(('127.0.0.1', port))
            client.settimeout(10)
            client.sendall(payload)
            echo = b''
            while len(echo) < len(payload):
                data = client.recv(65536)
                if not data:
                    break
                echo += data
        finally:
            client.close()
        server.join(timeout=10)
        return received.get('data'), echo, client

    @pytest.mark.parametrize('mode', ['hybrid', 'format'])
    def test_bulk_round_trip(self, mode):
        payload = b'bulk payload ' * 4096  # ~53 KiB, many records
        got, echo, client = self._run(payload, mode)
        assert got == payload
        assert echo == payload
        assert client.negotiated_mode == mode
        assert client.negotiated_format == 'manual-http'

    def test_server_learns_a_non_default_format(self):
        """The server is told nothing; it recovers the format from the first
        record."""
        got, echo, client = self._run(b'a non-default format', 'hybrid',
                                      format='words')
        assert got == b'a non-default format'
        assert echo == got
        assert client.negotiated_format == 'words'

    def test_wrong_server_id_gets_no_reply(self):
        """A client with the wrong connection string times out rather than
        receiving an error that would confirm the server."""
        private, _ = fteproxy.generate_server_key()
        _, other_public = fteproxy.generate_server_key()

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        replies = {}

        def serve():
            conn, _ = listener.accept()
            wrapped = fteproxy.wrap_socket(conn, server_key=private)
            wrapped.settimeout(10)
            try:
                replies['recv'] = wrapped.recv(65536)
            except socket.timeout:
                replies['recv'] = 'timeout'
            finally:
                conn.close()

        server = threading.Thread(target=serve)
        server.start()

        previous = fteproxy.conf.getValue('runtime.fteproxy.handshake.timeout')
        fteproxy.conf.setValue('runtime.fteproxy.handshake.timeout', 1)
        client = fteproxy.wrap_socket(socket.socket(), server_id=other_public)
        try:
            with pytest.raises(fteproxy.HandshakeFailedException):
                client.connect(('127.0.0.1', port))
        finally:
            fteproxy.conf.setValue('runtime.fteproxy.handshake.timeout', previous)
            client.close()
            server.join(timeout=15)
            listener.close()
        # The server read and discarded, then reported EOF; it never replied.
        assert replies.get('recv') == b''

    def test_wrap_socket_needs_exactly_one_role(self):
        private, public = fteproxy.generate_server_key()
        with pytest.raises(fteproxy.InvalidRoleException):
            fteproxy.wrap_socket(socket.socket())
        with pytest.raises(fteproxy.InvalidRoleException):
            fteproxy.wrap_socket(socket.socket(), server_key=private,
                                 server_id=public)

    def test_server_id_accepts_base64url(self):
        import base64

        _, public = fteproxy.generate_server_key()
        text = base64.urlsafe_b64encode(public).rstrip(b'=').decode('ascii')
        assert len(text) == 43
        assert fteproxy._as_key_bytes(text, 'server_id') == public
