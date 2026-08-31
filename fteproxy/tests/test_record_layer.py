#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the FTE record layer encoding/decoding.
"""

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
        fixed_slice = fteproxy.defs.getFixedSlice(language)
        cipher = fteproxy._make_cipher(regex, fixed_slice, key)
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
    """Cipher stub that decrypts a fixed-size covertext frame to itself."""

    def __init__(self, cell_size=4):
        self.output_format = _Format(cell_size)

    def decrypt(self, covertext):
        return covertext


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
