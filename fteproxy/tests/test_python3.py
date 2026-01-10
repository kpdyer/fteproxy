#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests specific to Python 3 compatibility.
"""

import unittest
import sys


class TestPython3Compatibility(unittest.TestCase):
    """Test Python 3 specific functionality."""

    def test_python_version(self):
        """Ensure we're running Python 3.8+"""
        self.assertGreaterEqual(sys.version_info.major, 3)
        self.assertGreaterEqual(sys.version_info.minor, 8)

    def test_bytes_key_config(self):
        """Test that the encryption key is properly stored as bytes."""
        import fteproxy.conf
        key = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)

    def test_bytes_hex_conversion(self):
        """Test bytes to hex and back conversion (Python 3 style)."""
        original = b'\xff' * 16 + b'\x00' * 16
        hex_str = original.hex()
        self.assertIsInstance(hex_str, str)
        self.assertEqual(len(hex_str), 64)
        
        restored = bytes.fromhex(hex_str)
        self.assertEqual(original, restored)

    def test_string_rjust(self):
        """Test that string rjust works correctly."""
        test_str = "test"
        padded = test_str.rjust(10, '0')
        self.assertEqual(len(padded), 10)
        self.assertEqual(padded, "000000test")

    def test_negotiate_cell_string_handling(self):
        """Test NegotiateCell string operations."""
        import fteproxy
        cell = fteproxy.NegotiateCell()
        cell.setDefFile("20131224")
        cell.setLanguage("manual-http")
        
        cell_str = cell.toString()
        self.assertEqual(len(cell_str), fteproxy.NegotiateCell._CELL_SIZE)
        
        # Verify padding
        padding_len = fteproxy.NegotiateCell._PADDING_LEN
        padding_char = fteproxy.NegotiateCell._PADDING_CHAR
        self.assertEqual(cell_str[:padding_len], padding_char * padding_len)

    def test_unicode_handling(self):
        """Test that unicode strings work correctly."""
        test_str = "Hello, 世界! 🌍"
        encoded = test_str.encode('utf-8')
        self.assertIsInstance(encoded, bytes)
        
        decoded = encoded.decode('utf-8')
        self.assertEqual(test_str, decoded)

    def test_dict_keys_iteration(self):
        """Test that dict.keys() returns a view that can be iterated."""
        import fteproxy.defs
        definitions = fteproxy.defs.load_definitions()
        keys = definitions.keys()
        
        # In Python 3, .keys() returns a view, not a list
        # Should be iterable
        key_list = list(keys)
        self.assertGreater(len(key_list), 0)
        
        # Should be able to iterate multiple times
        for key in definitions.keys():
            self.assertIsInstance(key, str)
            break

    def test_print_function(self):
        """Test that print is a function (not a statement)."""
        import io
        import contextlib
        
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            print("test output")
        
        output = f.getvalue()
        self.assertEqual(output.strip(), "test output")


class TestNetworkIOBytes(unittest.TestCase):
    """Test that network I/O uses bytes correctly."""

    def test_recvall_returns_bytes(self):
        """Test that recvall_from_socket returns bytes."""
        import socket
        import fteproxy.network_io
        
        # Create a socket pair for testing
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('127.0.0.1', 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]
        
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(('127.0.0.1', port))
        
        conn, _ = server_sock.accept()
        
        # Send some data
        test_data = b'Hello, Python 3!'
        client_sock.sendall(test_data)
        
        # Receive using our function
        is_alive, received = fteproxy.network_io.recvall_from_socket(conn, select_timeout=1.0)
        
        self.assertTrue(is_alive)
        self.assertIsInstance(received, bytes)
        self.assertEqual(received, test_data)
        
        # Cleanup
        client_sock.close()
        conn.close()
        server_sock.close()


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(TestPython3Compatibility))
    suite.addTest(loader.loadTestsFromTestCase(TestNetworkIOBytes))
    return suite


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())
