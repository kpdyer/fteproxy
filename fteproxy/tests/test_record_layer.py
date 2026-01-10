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
    
    pairs = []
    definitions = fteproxy.defs.load_definitions()
    for language in definitions.keys():
        regex = fteproxy.defs.getRegex(language)
        fixed_slice = fteproxy.defs.getFixedSlice(language)
        regex_encoder = fte.Encoder(regex, fixed_slice)
        encoder = fteproxy.record_layer.Encoder(encoder=regex_encoder)
        decoder = fteproxy.record_layer.Decoder(decoder=regex_encoder)
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
