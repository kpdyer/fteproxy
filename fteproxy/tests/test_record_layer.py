#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the FTE record layer encoding/decoding.
"""

import struct

import pytest
import fte

import fteproxy.conf
import fteproxy.defs
import fteproxy.record_layer


# Test parameters
START = 0
ITERATIONS = 2048
STEP = 64


@pytest.fixture
def record_layer_pairs():
    """Create encoder/decoder pairs for all defined languages."""
    fteproxy.conf.setValue('runtime.mode', 'client')
    
    key = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')
    pairs = []
    definitions = fteproxy.defs.load_definitions()
    for language in definitions.keys():
        regex = fteproxy.defs.getRegex(language)
        length = fteproxy.defs.getLength(language)
        cipher = fteproxy._make_cipher(regex, length, key)
        encoder = fteproxy.record_layer.Encoder(cipher=cipher)
        decoder = fteproxy.record_layer.Decoder(cipher=cipher)
        pairs.append((language, encoder, decoder))
    
    return pairs


class TestRecordLayer:
    """Tests for FTE record layer."""

    def test_basic_encode_decode(self, record_layer_pairs):
        """Test basic encoding and decoding of data."""
        for language, encoder, decoder in record_layer_pairs:
            for j in range(START, ITERATIONS, STEP):
                plaintext = b'X' * j + b'Y'
                encoder.push(plaintext)
                
                # Pop all encoded data and push to decoder
                while True:
                    data = encoder.pop()
                    if not data:
                        break
                    decoder.push(data)
                
                # Pop all decoded data
                decoded = b''
                while True:
                    data = decoder.pop()
                    if not data:
                        break
                    decoded += data
                
                assert plaintext == decoded, f"Failed for {language}: {plaintext} != {decoded}"

    def test_concatenated_messages(self, record_layer_pairs):
        """Test encoding and decoding of concatenated messages."""
        for language, encoder, decoder in record_layer_pairs:
            for j in range(START, ITERATIONS, STEP):
                plaintext = b'X' * j + b'Y'
                encoder.push(plaintext)
                
                # Collect all encoded data
                encoded = b''
                while True:
                    data = encoder.pop()
                    if not data:
                        break
                    encoded += data
                
                # Push all at once and decode
                decoder.push(encoded)
                decoded = b''
                while True:
                    data = decoder.pop()
                    if not data:
                        break
                    decoded += data
                
                assert plaintext == decoded, f"Failed for {language}"


class _Format:
    """Minimal output-format stub exposing the frame size the Decoder reads."""

    def __init__(self, max_length):
        self.max_length = max_length


class _RaisingCipher:
    """Cipher stub whose decrypt() always raises a given exception."""

    def __init__(self, exc, frame_size=4):
        self._exc = exc
        self.output_format = _Format(frame_size)

    def decrypt(self, covertext):
        raise self._exc


class _FixedCellCipher:
    """Cipher stub for a fixed-size covertext frame. Its plaintext seals the
    covertext bytes so the Decoder's unseal step recovers them."""

    def __init__(self, cell_size=4):
        self.output_format = _Format(cell_size)

    def decrypt(self, covertext):
        return struct.pack('>I', len(covertext)) + covertext


class TestDecoderExceptionHandling:
    """Regression tests for Decoder.pop() exception semantics."""

    def test_unrecoverable_error_not_swallowed_in_onecell_mode(self):
        """A fatal decryption error must not be silently swallowed.

        ``fatal_error()`` raises ``SystemExit``; a ``break`` in a ``finally``
        block swallows it and lets pop() return normally, silently discarding a
        fatal condition. With ``oneCell=True`` (the negotiation path) the error
        must still propagate. ``fte.MessageTooLargeError`` is the libfte 0.4
        successor to 0.3's ``UnrecoverableDecryptionError``.
        """
        decoder = fteproxy.record_layer.Decoder(
            cipher=_RaisingCipher(fte.MessageTooLargeError("boom")))
        decoder.push(b'some-ciphertext-bytes')

        with pytest.raises(SystemExit):
            decoder.pop(oneCell=True)

    def test_onecell_returns_exactly_one_cell(self):
        """oneCell=True returns a single decoded cell and advances the buffer."""
        decoder = fteproxy.record_layer.Decoder(cipher=_FixedCellCipher(4))
        decoder.push(b'AAAABBBBCCCC')

        assert decoder.pop(oneCell=True) == b'AAAA'
        assert decoder._buffer == b'BBBBCCCC'

    def test_multicell_drains_entire_buffer(self):
        """oneCell=False drains every cell from the buffer."""
        decoder = fteproxy.record_layer.Decoder(cipher=_FixedCellCipher(4))
        decoder.push(b'AAAABBBBCCCC')

        assert decoder.pop() == b'AAAABBBBCCCC'
        assert decoder._buffer == b''


class TestHybridRecordLayer:
    """The hybrid framing: a formatted header covertext + a raw AES-GCM body."""

    def _pair(self, language='manual-http-request'):
        fteproxy.conf.setValue('runtime.mode', 'client')
        key = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')
        pattern = fteproxy.defs.getRegex(language)
        length = fteproxy.defs.getLength(language)
        header = fteproxy._make_cipher(pattern, length, key)
        body = fteproxy._make_body_cipher(key)
        encoder = fteproxy.record_layer.Encoder(cipher=header, body_cipher=body)
        decoder = fteproxy.record_layer.Decoder(cipher=header, body_cipher=body)
        return encoder, decoder

    def test_roundtrip_various_sizes(self):
        encoder, decoder = self._pair()
        for j in range(0, 8192, 256):
            payload = b'X' * j + b'Y'
            encoder.push(payload)
            wire = b''
            while True:
                data = encoder.pop()
                if not data:
                    break
                wire += data
            decoder.push(wire)
            out = b''
            while True:
                data = decoder.pop()
                if not data:
                    break
                out += data
            assert out == payload, f"hybrid roundtrip failed at {len(payload)} bytes"

    def test_header_is_formatted_body_is_raw(self):
        """The record opens with a valid target-format covertext; the bulk is raw."""
        encoder, decoder = self._pair()
        encoder.push(b'Z' * 4000)
        wire = encoder.pop()
        assert wire[:5] == b'GET /'          # looks like the HTTP request format
        assert len(wire) < 4000 * 1.2        # near-1x expansion (raw body)

    def test_partial_arrival_reassembles(self):
        """A record split across many small reads still reassembles."""
        encoder, decoder = self._pair()
        payload = (b'the quick brown fox 0123456789 ' * 700)  # ~21 KiB, multi-record
        encoder.push(payload)
        wire = encoder.pop()
        out = b''
        for i in range(0, len(wire), 333):
            decoder.push(wire[i:i + 333])
            out += decoder.pop()
        assert out == payload

    def test_reordered_record_is_rejected(self):
        """A record moved out of its stream position fails the body auth."""
        encoder, _ = self._pair()
        encoder.push(b'first'); r0 = encoder.pop()    # seq 0
        encoder.push(b'second'); r1 = encoder.pop()   # seq 1

        # In order: both records decode.
        d = self._pair()[1]
        d.push(r0 + r1)
        assert d.pop() == b'firstsecond'

        # Swapped: the record built at seq 1 arrives where seq 0 is expected, so
        # its body AEAD (seq as associated data) fails and nothing decodes.
        d2 = self._pair()[1]
        d2.push(r1 + r0)
        assert d2.pop() == b''


def test_seal_fills_covertext_with_random_not_padding():
    """A short message fills the covertext with random format text, so there is
    no 'GET /0000...' low-rank padding run in either mode."""
    fteproxy.conf.setValue('runtime.mode', 'client')
    fteproxy.defs.load_definitions()
    key = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')
    pattern = fteproxy.defs.getRegex('http-simple-request')
    header = fteproxy._make_cipher(pattern, 256, key)

    def path_of(covertext):
        return covertext[len(b'GET /'):covertext.index(b' HTTP')]

    fmt_enc = fteproxy.record_layer.Encoder(cipher=header)
    fmt_enc.push(b'hi')
    fmt_path = path_of(fmt_enc.pop())

    body = fteproxy._make_body_cipher(key)
    hyb_enc = fteproxy.record_layer.Encoder(cipher=header, body_cipher=body)
    hyb_enc.push(b'hi')
    hyb_path = path_of(hyb_enc.pop()[:256])

    for path in (fmt_path, hyb_path):
        assert len(path) > 100        # the path fills the covertext capacity
        assert len(set(path)) > 15    # random-looking, not a single-char run
