#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Encode/decode tests for the legacy 20260110 and 20131224 catalogs.

The current protocol catalog has separate per-protocol tests.
"""

import pytest

import fteproxy
from fteproxy.tests import conftest
import fteproxy.conf
import fteproxy.defs
import fteproxy.record_layer


# Deterministic test key for direct libfte calls; runtime sessions derive their own.
_KEY = conftest.TEST_KEY


@pytest.fixture(autouse=True)
def _restore_release():
    """Put the process-wide definitions release back after every test here.

    This file exercises the comprehensive *shape* catalog, which stopped being
    the default in the 20260903 release, so every test in it selects 20260110
    (or 20131224) explicitly. Without this the selection would leak into every
    later test in the session, which would then quietly run against a release
    it never asked for.
    """
    previous = fteproxy.conf.getValue('fteproxy.defs.release')
    yield
    fteproxy.conf.setValue('fteproxy.defs.release', previous)


def _cipher(pattern, length):
    """Build a libfte 0.4 cipher (successor to ``fte.Encoder(pattern, length)``)."""
    return fteproxy._make_cipher(pattern, length, _KEY)


class TestBuiltinFormats:
    """Test all built-in formats from the 20260110 definitions."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up the test environment."""
        fteproxy.conf.setValue('fteproxy.defs.release', '20260110')

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
        length = fteproxy.defs.getLength(format_name)
        
        cipher = _cipher(regex, length)
        test_data = b"Hello, World!"
        
        ciphertext = cipher.encrypt(test_data)
        # Decode this fixed-length covertext for the alphabet check.
        text_portion = ciphertext[:length].decode('ascii', errors='ignore')
        assert len(text_portion) > 0
        # Check at least the beginning matches the pattern
        assert pattern_check(text_portion[:20]) or len(text_portion) < 20
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_words_format(self):
        """Test the words format produces space-separated words."""
        regex = fteproxy.defs.getRegex("words-request")
        length = fteproxy.defs.getLength("words-request")
        
        cipher = _cipher(regex, length)
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
        length = fteproxy.defs.getLength("sentences-request")
        
        cipher = _cipher(regex, length)
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
        length = fteproxy.defs.getLength("csv-request")
        
        cipher = _cipher(regex, length)
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
        length = fteproxy.defs.getLength("ip-address-request")
        
        cipher = _cipher(regex, length)
        test_data = b"Hi"
        
        ciphertext = cipher.encrypt(test_data)
        # Decode the fixed-length covertext.
        decoded = ciphertext[:length].decode('ascii', errors='ignore')
        
        # Should look like an IP address
        parts = decoded.split('.')
        assert len(parts) == 4
        assert all(part.isdigit() for part in parts)
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_domain_format(self):
        """Test the domain format produces domain-like output."""
        regex = fteproxy.defs.getRegex("domain-request")
        length = fteproxy.defs.getLength("domain-request")
        
        cipher = _cipher(regex, length)
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
        length = fteproxy.defs.getLength("email-simple-request")
        
        cipher = _cipher(regex, length)
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
        length = fteproxy.defs.getLength("url-path-request")
        
        cipher = _cipher(regex, length)
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
        length = fteproxy.defs.getLength("key-value-request")
        
        cipher = _cipher(regex, length)
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
        length = fteproxy.defs.getLength("timestamp-request")
        
        cipher = _cipher(regex, length)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        # Decode the fixed-length covertext.
        decoded = ciphertext[:length].decode('ascii', errors='ignore')
        
        # Should look like a timestamp
        parts = decoded.split(':')
        assert len(parts) == 3
        assert all(part.isdigit() for part in parts)
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_http_simple_request_format(self):
        """Test the HTTP request format produces HTTP-like output."""
        regex = fteproxy.defs.getRegex("http-simple-request")
        length = fteproxy.defs.getLength("http-simple-request")
        
        cipher = _cipher(regex, length)
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
        length = fteproxy.defs.getLength("ssh-request")
        
        cipher = _cipher(regex, length)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext[:length].decode('ascii', errors='ignore')
        
        # Should look like an SSH banner
        assert decoded.startswith('SSH-2.0-')
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_tls_sni_format(self):
        """Test the TLS SNI format produces domain-like output."""
        regex = fteproxy.defs.getRegex("tls-sni-request")
        length = fteproxy.defs.getLength("tls-sni-request")
        
        cipher = _cipher(regex, length)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext[:length].decode('ascii', errors='ignore')
        
        # Should look like subdomain.domain.tld
        parts = decoded.split('.')
        assert len(parts) == 3
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_smtp_format(self):
        """Test the SMTP format produces EHLO command-like output."""
        regex = fteproxy.defs.getRegex("smtp-request")
        length = fteproxy.defs.getLength("smtp-request")
        
        cipher = _cipher(regex, length)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext[:length].decode('ascii', errors='ignore')
        
        # Should look like SMTP EHLO command
        assert decoded.startswith('EHLO ')
        assert '.' in decoded
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data

    def test_ftp_format(self):
        """Test the FTP format produces FTP response-like output."""
        regex = fteproxy.defs.getRegex("ftp-response")
        length = fteproxy.defs.getLength("ftp-response")
        
        cipher = _cipher(regex, length)
        test_data = b"X"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext[:length].decode('ascii', errors='ignore')
        
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

    @pytest.mark.parametrize("protocol,expected_prefix", [
        ("ssh", "SSH-2.0-"),
        ("smtp", "EHLO "),
        ("ftp", "USER "),
    ])
    def test_protocol_request_format(self, protocol, expected_prefix):
        """Test protocol request formats produce expected output."""
        format_name = f"{protocol}-request"
        regex = fteproxy.defs.getRegex(format_name)
        length = fteproxy.defs.getLength(format_name)
        
        cipher = _cipher(regex, length)
        test_data = b"Test"
        
        ciphertext = cipher.encrypt(test_data)
        decoded = ciphertext[:length].decode('ascii', errors='ignore')
        
        assert decoded.startswith(expected_prefix)
        
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data


class TestFormatPairs:
    """Test that request/response format pairs work correctly."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up the test environment."""
        fteproxy.conf.setValue('fteproxy.defs.release', '20260110')

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
        req_length = fteproxy.defs.getLength(request_format)
        req_cipher = _cipher(req_regex, req_length)
        
        test_data = b"Test"
        ciphertext = req_cipher.encrypt(test_data)
        plaintext = req_cipher.decrypt(ciphertext)
        assert plaintext == test_data
        
        # Test response format
        resp_regex = fteproxy.defs.getRegex(response_format)
        resp_length = fteproxy.defs.getLength(response_format)
        resp_cipher = _cipher(resp_regex, resp_length)
        
        ciphertext = resp_cipher.encrypt(test_data)
        plaintext = resp_cipher.decrypt(ciphertext)
        assert plaintext == test_data


class TestLegacyFormats:
    """Load and use legacy definitions with the current wire protocol."""

    def test_legacy_20131224_formats(self):
        """Test that legacy 20131224 formats still work."""
        fteproxy.conf.setValue('fteproxy.defs.release', '20131224')
        
        # Test dummy format
        regex = fteproxy.defs.getRegex('dummy-request')
        assert regex == '^.+$'
        
        # Test manual-http-request
        regex = fteproxy.defs.getRegex('manual-http-request')
        assert 'HTTP' in regex


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_input(self):
        """Empty input round-trips; the record layer emits nothing for it."""
        regex = "^[a-z]+$"
        length = 256

        cipher = _cipher(regex, length)
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
        length = 256

        cipher = _cipher(regex, length)
        encoder = fteproxy.record_layer.Encoder(cipher=cipher)
        decoder = fteproxy.record_layer.Decoder(cipher=cipher)
        test_data = b"X" * 500
        encoder.push(test_data)
        decoder.push(encoder.pop())
        assert decoder.pop() == test_data

    def test_binary_data(self):
        """All 256 byte values round-trip through the record layer."""
        regex = "^[a-z]+$"
        length = 256

        cipher = _cipher(regex, length)
        encoder = fteproxy.record_layer.Encoder(cipher=cipher)
        decoder = fteproxy.record_layer.Decoder(cipher=cipher)
        test_data = bytes(range(256))
        encoder.push(test_data)
        decoder.push(encoder.pop())
        assert decoder.pop() == test_data

    def test_unicode_data(self):
        """Test encoding unicode data."""
        regex = "^[a-z]+$"
        length = 256
        
        cipher = _cipher(regex, length)
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
        length = 256
        
        cipher = _cipher(regex, length)
        ciphertext = cipher.encrypt(test_data)
        plaintext = cipher.decrypt(ciphertext)
        assert plaintext == test_data


class TestAllDefinedFormats:
    """Round-trip every entry in the 20260110 shape catalog."""

    def test_all_formats_in_20260110(self):
        """Test that all formats in 20260110.json work correctly."""
        fteproxy.conf.setValue('fteproxy.defs.release', '20260110')
        definitions = fteproxy.defs.load_definitions()
        
        failed = []
        for format_name in definitions.keys():
            try:
                regex = fteproxy.defs.getRegex(format_name)
                length = fteproxy.defs.getLength(format_name)
                
                cipher = _cipher(regex, length)
                test_data = b"Test"
                ciphertext = cipher.encrypt(test_data)
                plaintext = cipher.decrypt(ciphertext)
                
                if plaintext != test_data:
                    failed.append((format_name, "roundtrip failed"))
            except Exception as e:
                failed.append((format_name, str(e)))
        
        if failed:
            pytest.fail(f"Failed formats: {failed}")


class TestDefinitionsCapacity:
    """Every shipped format must be able to carry a handshake."""

    @pytest.mark.parametrize('release', ['20260110', '20131224'])
    def test_shipped_releases_pass_the_load_check(self, release):
        previous = fteproxy.conf.getValue('fteproxy.defs.release')
        try:
            fteproxy.conf.setValue('fteproxy.defs.release', release)
            definitions = fteproxy.defs.load_definitions()
            fteproxy.defs.check_capacities(definitions)
        finally:
            fteproxy.conf.setValue('fteproxy.defs.release', previous)

    def test_a_too_small_format_is_refused(self):
        """A format that cannot hold a client hello would fail as a client
        that hangs, so it fails at load instead."""
        with pytest.raises(fteproxy.defs.DefinitionsError) as excinfo:
            fteproxy.defs.check_capacities(
                {'tiny-request': {'regex': '^[01]+$', 'length': 300}})
        assert 'tiny-request' in str(excinfo.value)

    def test_an_uncompilable_format_is_refused(self):
        with pytest.raises(fteproxy.defs.DefinitionsError):
            fteproxy.defs.check_capacities(
                {'broken-request': {'regex': '^[a-z', 'length': 256}})

    def test_every_base_name_has_both_directions(self):
        definitions = fteproxy.defs.load_definitions()
        bases = fteproxy.defs.base_names(definitions)
        for base in bases:
            assert base + '-request' in definitions
            assert base + '-response' in definitions
        # Nothing in the file is left out of a pair.
        assert len(bases) * 2 == len(definitions)

    def test_a_client_hello_fits_every_format(self):
        """The check is a proxy for this: the largest hello a shipped base
        name can produce, plus the record layer's seal, must fit."""
        import fteproxy.handshake as hs
        import fteproxy.record_layer as rl

        definitions = fteproxy.defs.load_definitions()
        longest = max(fteproxy.defs.base_names(definitions), key=len)
        hello = hs.ClientHello(mode='hybrid', defs=20260110, format=longest,
                               client_public=b'\x00' * 32,
                               epoch=hs.current_epoch()).encode()
        needed = len(hello) + rl._SEAL_OVERHEAD
        assert needed <= fteproxy.defs.MIN_CAPACITY
        for name in definitions:
            capacity = _cipher(fteproxy.defs.getRegex(name),
                               fteproxy.defs.getLength(name)).max_plaintext_bytes
            assert capacity >= needed, name
