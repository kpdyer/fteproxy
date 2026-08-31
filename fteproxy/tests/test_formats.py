#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests for all regex formats defined in the defs files.
Verifies that each format can successfully encode and decode data.
"""

import pytest
import json
import os
import re

import fte
import fteproxy
import fteproxy.conf
import fteproxy.defs
import fteproxy.record_layer


# libfte 0.4 requires an explicit key; use fteproxy's configured shared key.
_KEY = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')


def _cipher(pattern, fixed_slice):
    """Build a libfte 0.4 cipher (successor to ``fte.Encoder(pattern, slice)``)."""
    return fteproxy._make_cipher(pattern, fixed_slice, _KEY)


class TestBuiltinFormats:
    """Test all built-in formats from the 20260110 definitions."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up the test environment."""
        fteproxy.conf.setValue('fteproxy.defs.release', '20260110')
        fteproxy.defs._definitions = None  # Reset cache

    @pytest.mark.parametrize("format_name,pattern_check", [
        ("lowercase-request", lambda s: s.islower() and s.isalpha()),
        ("uppercase-request", lambda s: s.isupper() and s.isalpha()),
        ("digits-request", lambda s: s.isdigit()),
        ("alphanumeric-request", lambda s: s.isalnum()),
        ("hex-request", lambda s: all(c in '0123456789abcdef' for c in s)),
        ("binary-request", lambda s: all(c in '01' for c in s)),
        ("base64-request", lambda s: all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/' for c in s)),
    ])
    def test_format_encoding(self, format_name, pattern_check):
        """Test encoding with various formats."""
        regex = fteproxy.defs.getRegex(format_name)
        fixed_slice = fteproxy.defs.getFixedSlice(format_name)
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"Hello, World!"
        
        ciphertext = cipher.encrypt(test_data)
        # Extract only the text portion (ciphertext may include binary padding)
        text_portion = ciphertext[:fixed_slice].decode('ascii', errors='ignore')
        assert len(text_portion) > 0
        # Check at least the beginning matches the pattern
        assert pattern_check(text_portion[:20]) or len(text_portion) < 20
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_words_format(self):
        """Test the words format produces space-separated words."""
        regex = fteproxy.defs.getRegex("words-request")
        fixed_slice = fteproxy.defs.getFixedSlice("words-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"Secret message"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext.decode('ascii')
        
        # Should contain spaces and lowercase letters
        assert ' ' in decoded
        assert all(c in 'abcdefghijklmnopqrstuvwxyz ' for c in decoded)
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_sentences_format(self):
        """Test the sentences format produces sentence-like output."""
        regex = fteproxy.defs.getRegex("sentences-request")
        fixed_slice = fteproxy.defs.getFixedSlice("sentences-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"Test"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext.decode('ascii')
        
        # Should end with a period and have capital letters
        assert decoded.endswith('.')
        assert any(c.isupper() for c in decoded)
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_csv_format(self):
        """Test the CSV format produces comma-separated output."""
        regex = fteproxy.defs.getRegex("csv-request")
        fixed_slice = fteproxy.defs.getFixedSlice("csv-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"Data"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext.decode('ascii')
        
        # Should contain commas
        assert ',' in decoded
        fields = decoded.split(',')
        assert len(fields) >= 2
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_ip_address_format(self):
        """Test the IP address format produces dotted decimal."""
        regex = fteproxy.defs.getRegex("ip-address-request")
        fixed_slice = fteproxy.defs.getFixedSlice("ip-address-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"Hi"
        
        ciphertext = cipher.encrypt(test_data)
        # Only decode the fixed_slice portion (rest may be binary padding)
        decoded = ciphertext[:fixed_slice].decode('ascii', errors='ignore')
        
        # Should look like an IP address
        parts = decoded.split('.')
        assert len(parts) == 4
        assert all(part.isdigit() for part in parts)
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_domain_format(self):
        """Test the domain format produces domain-like output."""
        regex = fteproxy.defs.getRegex("domain-request")
        fixed_slice = fteproxy.defs.getFixedSlice("domain-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext.decode('ascii')
        
        # Should look like a domain
        assert '.' in decoded
        parts = decoded.split('.')
        assert len(parts) == 2
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_email_format(self):
        """Test the email format produces email-like output."""
        regex = fteproxy.defs.getRegex("email-simple-request")
        fixed_slice = fteproxy.defs.getFixedSlice("email-simple-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext.decode('ascii')
        
        # Should look like an email
        assert '@' in decoded
        assert '.' in decoded
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_url_path_format(self):
        """Test the URL path format produces path-like output."""
        regex = fteproxy.defs.getRegex("url-path-request")
        fixed_slice = fteproxy.defs.getFixedSlice("url-path-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"Hello"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext.decode('ascii')
        
        # Should start with / and look like a path
        assert decoded.startswith('/')
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_key_value_format(self):
        """Test the key-value format produces key=value output."""
        regex = fteproxy.defs.getRegex("key-value-request")
        fixed_slice = fteproxy.defs.getFixedSlice("key-value-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext.decode('ascii')
        
        # Should contain =
        assert '=' in decoded
        parts = decoded.split('=')
        assert len(parts) == 2
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_timestamp_format(self):
        """Test the timestamp format produces time-like output."""
        regex = fteproxy.defs.getRegex("timestamp-request")
        fixed_slice = fteproxy.defs.getFixedSlice("timestamp-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        # Only decode the fixed_slice portion (rest may be binary padding)
        decoded = ciphertext[:fixed_slice].decode('ascii', errors='ignore')
        
        # Should look like a timestamp
        parts = decoded.split(':')
        assert len(parts) == 3
        assert all(part.isdigit() for part in parts)
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_http_simple_request_format(self):
        """Test the HTTP request format produces HTTP-like output."""
        regex = fteproxy.defs.getRegex("http-simple-request")
        fixed_slice = fteproxy.defs.getFixedSlice("http-simple-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext.decode('ascii')
        
        # Should look like an HTTP request
        assert decoded.startswith('GET /')
        assert 'HTTP/1.1' in decoded
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_ssh_format(self):
        """Test the SSH format produces SSH banner-like output."""
        regex = fteproxy.defs.getRegex("ssh-request")
        fixed_slice = fteproxy.defs.getFixedSlice("ssh-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext[:fixed_slice].decode('ascii', errors='ignore')
        
        # Should look like an SSH banner
        assert decoded.startswith('SSH-2.0-')
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_tls_sni_format(self):
        """Test the TLS SNI format produces domain-like output."""
        regex = fteproxy.defs.getRegex("tls-sni-request")
        fixed_slice = fteproxy.defs.getFixedSlice("tls-sni-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext[:fixed_slice].decode('ascii', errors='ignore')
        
        # Should look like subdomain.domain.tld
        parts = decoded.split('.')
        assert len(parts) == 3
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_smtp_format(self):
        """Test the SMTP format produces EHLO command-like output."""
        regex = fteproxy.defs.getRegex("smtp-request")
        fixed_slice = fteproxy.defs.getFixedSlice("smtp-request")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext[:fixed_slice].decode('ascii', errors='ignore')
        
        # Should look like SMTP EHLO command
        assert decoded.startswith('EHLO ')
        assert '.' in decoded
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_ftp_format(self):
        """Test the FTP format produces FTP response-like output."""
        regex = fteproxy.defs.getRegex("ftp-response")
        fixed_slice = fteproxy.defs.getFixedSlice("ftp-response")
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext[:fixed_slice].decode('ascii', errors='ignore')
        
        # Should look like FTP welcome banner
        assert decoded.startswith('220 ')
        assert 'ready' in decoded
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data


class TestProtocolFormats:
    """Test all protocol-like formats."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up the test environment."""
        fteproxy.conf.setValue('fteproxy.defs.release', '20260110')
        fteproxy.defs._definitions = None  # Reset cache

    @pytest.mark.parametrize("protocol,expected_prefix", [
        ("ssh", "SSH-2.0-"),
        ("smtp", "EHLO "),
        ("ftp", "USER "),
    ])
    def test_protocol_request_format(self, protocol, expected_prefix):
        """Test protocol request formats produce expected output."""
        format_name = f"{protocol}-request"
        regex = fteproxy.defs.getRegex(format_name)
        fixed_slice = fteproxy.defs.getFixedSlice(format_name)
        
        cipher = _cipher(regex, fixed_slice)
        test_data = b"Test"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext[:fixed_slice].decode('ascii', errors='ignore')
        
        assert decoded.startswith(expected_prefix)
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data


class TestFormatPairs:
    """Test that request/response format pairs work correctly."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up the test environment."""
        fteproxy.conf.setValue('fteproxy.defs.release', '20260110')
        fteproxy.defs._definitions = None  # Reset cache

    @pytest.mark.parametrize("format_base", [
        "lowercase",
        "uppercase",
        "alphanumeric",
        "hex",
        "digits",
        "binary",
        "base64",
        "words",
        "csv",
        "ip-address",
        "domain",
        "url-path",
        "key-value",
        "timestamp",
    ])
    def test_request_response_roundtrip(self, format_base):
        """Test encoding/decoding with both request and response formats."""
        request_format = f"{format_base}-request"
        response_format = f"{format_base}-response"
        
        # Test request format
        req_regex = fteproxy.defs.getRegex(request_format)
        req_slice = fteproxy.defs.getFixedSlice(request_format)
        req_cipher = _cipher(req_regex, req_slice)
        
        test_data = b"Test"
        ciphertext = req_cipher.encrypt(test_data)
        plaintext = req_cipher.decrypt(ciphertext)
        assert plaintext == test_data
        
        # Test response format
        resp_regex = fteproxy.defs.getRegex(response_format)
        resp_slice = fteproxy.defs.getFixedSlice(response_format)
        resp_cipher = _cipher(resp_regex, resp_slice)
        
        ciphertext = resp_cipher.encrypt(test_data)
        plaintext = resp_cipher.decrypt(ciphertext)
        assert plaintext == test_data


class TestLegacyFormats:
    """Test backward compatibility with legacy format definitions."""

    def test_legacy_20131224_formats(self):
        """Test that legacy 20131224 formats still work."""
        fteproxy.conf.setValue('fteproxy.defs.release', '20131224')
        fteproxy.defs._definitions = None  # Reset cache
        
        # Test dummy format
        regex = fteproxy.defs.getRegex('dummy-request')
        assert regex == '^\\C+$'
        
        # Test manual-http-request
        regex = fteproxy.defs.getRegex('manual-http-request')
        assert 'HTTP' in regex


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_input(self):
        """Empty input round-trips; the record layer emits nothing for it."""
        regex = "^[a-z]+$"
        fixed_slice = 256

        cipher = _cipher(regex, fixed_slice)
        # The record layer emits no covertext for an empty push.
        encoder = fteproxy.record_layer.Encoder(cipher=cipher)
        encoder.push(b"")
        assert encoder.pop() == b""
        # The raw engine still emits a full covertext that decrypts to empty.
        assert cipher.decrypt(cipher.encrypt(b"")) == b""

    def test_large_input(self):
        """Data larger than one covertext's capacity round-trips via the record
        layer, which chunks it into multiple fixed-length cells.

        libfte 0.4 caps a single ``encrypt`` at the format's capacity (there is
        no unformatted-overflow escape hatch), so chunking is the record layer's
        job, not the engine's.
        """
        regex = "^[a-z]+$"
        fixed_slice = 256

        cipher = _cipher(regex, fixed_slice)
        encoder = fteproxy.record_layer.Encoder(cipher=cipher)
        decoder = fteproxy.record_layer.Decoder(cipher=cipher)
        test_data = b"X" * 500
        encoder.push(test_data)
        decoder.push(encoder.pop())
        assert decoder.pop() == test_data

    def test_binary_data(self):
        """All 256 byte values round-trip through the record layer."""
        regex = "^[a-z]+$"
        fixed_slice = 256

        cipher = _cipher(regex, fixed_slice)
        encoder = fteproxy.record_layer.Encoder(cipher=cipher)
        decoder = fteproxy.record_layer.Decoder(cipher=cipher)
        test_data = bytes(range(256))
        encoder.push(test_data)
        decoder.push(encoder.pop())
        assert decoder.pop() == test_data

    def test_unicode_data(self):
        """Test encoding unicode data."""
        regex = "^[a-z]+$"
        fixed_slice = 256
        
        cipher = _cipher(regex, fixed_slice)
        test_data = "Hello, 世界! 🌍".encode('utf-8')
        ciphertext = cipher.encrypt(test_data)
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    @pytest.mark.parametrize("test_data", [
        b"A",
        b"AB",
        b"ABC",
        b"ABCD",
        b"Hello, World!",
        b"\x00\x01\x02\x03\x04",
    ])
    def test_various_input_sizes(self, test_data):
        """Test encoding data of various sizes."""
        regex = "^[a-z]+$"
        fixed_slice = 256
        
        cipher = _cipher(regex, fixed_slice)
        ciphertext = cipher.encrypt(test_data)
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data


class TestAllDefinedFormats:
    """Exhaustively test all formats in all definition files."""

    def test_all_formats_in_20260110(self):
        """Test that all formats in 20260110.json work correctly."""
        fteproxy.conf.setValue('fteproxy.defs.release', '20260110')
        fteproxy.defs._definitions = None  # Reset cache
        definitions = fteproxy.defs.load_definitions()
        
        failed = []
        for format_name in definitions.keys():
            try:
                regex = fteproxy.defs.getRegex(format_name)
                fixed_slice = fteproxy.defs.getFixedSlice(format_name)
                
                cipher = _cipher(regex, fixed_slice)
                test_data = b"Test"
                ciphertext = cipher.encrypt(test_data)
                plaintext = cipher.decrypt(ciphertext)
                
                if plaintext != test_data:
                    failed.append((format_name, "roundtrip failed"))
            except Exception as e:
                failed.append((format_name, str(e)))
        
        if failed:
            pytest.fail(f"Failed formats: {failed}")
