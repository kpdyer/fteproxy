#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the FTE record layer encoding/decoding.
"""

import logging
import struct

import pytest
import fte

import fteproxy
from fteproxy.tests import conftest
import fteproxy.conf
import fteproxy.defs
import fteproxy.record_layer


# Test parameters
START = 0
ITERATIONS = 2048
STEP = 64

#: The comprehensive *shape* catalog. These tests exercise the record layer
#: against ``manual-http-*`` and against every entry in one release, which is
#: what this catalog is: 46 formats of every shape, from a single-character
#: alphabet to a full HTTP message. It stopped being the shipped default when
#: the 20260903 cleartext-protocol release landed, so it is selected by name
#: here rather than inherited.
SHAPE_CATALOG = '20260110'
SHAPE_FORMAT = 'manual-http-request'


@pytest.fixture(autouse=True)
def _shape_catalog():
    """Point the loader at the shape catalog for this module, then restore."""
    previous = fteproxy.conf.getValue('fteproxy.defs.release')
    saved = fteproxy.defs._definitions
    fteproxy.conf.setValue('fteproxy.defs.release', SHAPE_CATALOG)
    fteproxy.defs._definitions = None
    yield
    fteproxy.conf.setValue('fteproxy.defs.release', previous)
    fteproxy.defs._definitions = saved


@pytest.fixture
def record_layer_pairs():
    """Create encoder/decoder pairs for all defined languages."""
    
    key = conftest.TEST_KEY
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
    """Cipher stub for a fixed-size covertext frame. Its plaintext seals a DATA
    record whose payload is the covertext bytes (length, then the stream
    position it is decrypted at, then the record type) so the Decoder's unseal
    and type-split steps recover them."""

    def __init__(self, cell_size=4):
        self.output_format = _Format(cell_size)
        self._seq = 0

    def decrypt(self, covertext):
        message = bytes((fteproxy.record_layer.DATA,)) + covertext
        sealed = struct.pack('>IQ', len(message), self._seq) + message
        self._seq += 1
        return sealed


class TestDecoderExceptionHandling:
    """Regression tests for Decoder.pop() exception semantics."""

    def test_unrecoverable_error_not_swallowed_in_onecell_mode(self):
        """A fatal decryption error must not be silently swallowed.

        ``fatal_error()`` raises ``SystemExit``; a ``break`` in a ``finally``
        block swallows it and lets pop() return normally, silently discarding a
        fatal condition. With ``oneCell=True`` (the negotiation path) the error
        must still propagate. ``fte.FormatContractError`` (a broken format
        provider) is the condition that keeps libfte 0.3's
        ``UnrecoverableDecryptionError`` semantics under 0.4.
        """
        decoder = fteproxy.record_layer.Decoder(
            cipher=_RaisingCipher(fte.FormatContractError("boom")))
        decoder.push(b'some-ciphertext-bytes')

        with pytest.raises(SystemExit):
            decoder.pop(limit=1)

    def test_limit_returns_exactly_one_record(self):
        """limit=1 returns a single decoded record and advances the buffer."""
        decoder = fteproxy.record_layer.Decoder(cipher=_FixedCellCipher(4))
        decoder.push(b'AAAABBBBCCCC')

        assert decoder.pop(limit=1) == b'AAAA'
        assert decoder._buffer == b'BBBBCCCC'

    def test_unlimited_drains_entire_buffer(self):
        """Without a limit every record in the buffer is drained."""
        decoder = fteproxy.record_layer.Decoder(cipher=_FixedCellCipher(4))
        decoder.push(b'AAAABBBBCCCC')

        assert decoder.pop() == b'AAAABBBBCCCC'
        assert decoder._buffer == b''


class TestHybridRecordLayer:
    """The hybrid framing: a formatted header covertext + a raw authenticated body."""

    def _pair(self, language=SHAPE_FORMAT):
        key = conftest.TEST_KEY
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

    def test_pending_header_is_decrypted_once(self):
        """A header whose body arrives over several reads is ranked and
        verified once, not once per partial delivery."""
        encoder, decoder = self._pair()
        real = decoder._cipher
        calls = []

        class Counting:
            output_format = real.output_format
            max_plaintext_bytes = real.max_plaintext_bytes

            def decrypt(self, covertext):
                calls.append(1)
                return real.decrypt(covertext)

        decoder._cipher = Counting()
        encoder.push(b'Q' * 5000)
        wire = encoder.pop()                     # 256-byte header + 5028-byte body
        decoder.push(wire[:300]); assert decoder.pop() == b''
        decoder.push(wire[300:600]); assert decoder.pop() == b''
        decoder.push(wire[600:]); assert decoder.pop() == b'Q' * 5000
        assert len(calls) == 1
        # And the next record is decrypted afresh.
        encoder.push(b'R' * 10); decoder.push(encoder.pop())
        assert decoder.pop() == b'R' * 10
        assert len(calls) == 2

    def test_oversized_body_length_is_rejected(self, caplog):
        """A header announcing a body larger than any record can carry is
        refused instead of buffering up to 4 GiB waiting for it."""
        encoder, decoder = self._pair()
        header = fteproxy.record_layer._seal(
            encoder._cipher, fteproxy.record_layer._OVERFLOW_LEN.pack(2 ** 32 - 1), 0)
        decoder.push(header + b'x' * 64)
        with caplog.at_level(logging.INFO, logger='fteproxy'):
            assert decoder.pop() == b''
        assert 'exceeds the record limit' in caplog.text
        # Fail-closed: the bad record marks the stream dead and drops the buffer.
        assert decoder.failed
        assert decoder._buffer == b''

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


class TestFormatModeRecordLayer:
    """'format' mode: one sealed covertext per record, stamped with its position."""

    def _pair(self, language=SHAPE_FORMAT):
        key = conftest.TEST_KEY
        cipher = fteproxy._make_cipher(
            fteproxy.defs.getRegex(language), fteproxy.defs.getLength(language), key)
        return (fteproxy.record_layer.Encoder(cipher=cipher),
                fteproxy.record_layer.Decoder(cipher=cipher))

    def test_reordered_or_replayed_record_is_rejected(self):
        encoder, _ = self._pair()
        encoder.push(b'first'); r0 = encoder.pop()    # seq 0
        encoder.push(b'second'); r1 = encoder.pop()   # seq 1

        d = self._pair()[1]
        d.push(r0 + r1)
        assert d.pop() == b'firstsecond'

        swapped = self._pair()[1]
        swapped.push(r1 + r0)
        assert swapped.pop() == b''

        replayed = self._pair()[1]
        replayed.push(r0 + r0)
        assert replayed.pop() == b'first'          # the replay is refused
        # Fail-closed: the duplicate marks the stream dead and drops the buffer.
        assert replayed.failed
        assert replayed._buffer == b''

    def test_multi_record_message_roundtrips(self):
        encoder, decoder = self._pair()
        payload = bytes(range(256)) * 8            # several records
        encoder.push(payload)
        decoder.push(encoder.pop())
        assert decoder.pop() == payload


def test_seal_fills_covertext_with_random_not_padding():
    """A short message fills the covertext with random format text, so there is
    no 'GET /0000...' low-rank padding run in either mode."""
    fteproxy.defs.load_definitions()
    key = conftest.TEST_KEY
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


class TestRecordTypes:
    """Every record carries a type byte; unknown types close the connection."""

    def _pair(self, hybrid=True, language=SHAPE_FORMAT):
        key = conftest.TEST_KEY
        cipher = fteproxy._make_cipher(
            fteproxy.defs.getRegex(language),
            fteproxy.defs.getLength(language), key)
        body = fteproxy._make_body_cipher(key) if hybrid else None
        return (fteproxy.record_layer.Encoder(cipher=cipher, body_cipher=body),
                fteproxy.record_layer.Decoder(cipher=cipher, body_cipher=body))

    @pytest.mark.parametrize('hybrid', [True, False])
    @pytest.mark.parametrize('record_type,payload', [
        (fteproxy.record_layer.DATA, b'application bytes'),
        (fteproxy.record_layer.OPEN, b'\x03\x0bexample.com\x01\xbb'),
        (fteproxy.record_layer.OPEN_RESULT, b'\x00'),
        (fteproxy.record_layer.PADDING, b'\x00' * 32),
        (fteproxy.record_layer.CLOSE, b''),
    ])
    def test_every_type_round_trips(self, hybrid, record_type, payload):
        encoder, decoder = self._pair(hybrid=hybrid)
        decoder.push(encoder.encode(record_type, payload))
        assert decoder.pop_records() == [(record_type, payload)]

    @pytest.mark.parametrize('hybrid', [True, False])
    def test_types_interleave_with_data(self, hybrid):
        encoder, decoder = self._pair(hybrid=hybrid)
        wire = encoder.encode(fteproxy.record_layer.OPEN, b'dest')
        encoder.push(b'payload')
        wire += encoder.pop()
        wire += encoder.encode(fteproxy.record_layer.CLOSE)
        decoder.push(wire)
        assert decoder.pop_records() == [
            (fteproxy.record_layer.OPEN, b'dest'),
            (fteproxy.record_layer.DATA, b'payload'),
            (fteproxy.record_layer.CLOSE, b''),
        ]

    @pytest.mark.parametrize('hybrid', [True, False])
    def test_unknown_type_raises(self, hybrid):
        """Only a peer with the session keys can produce one, so this is a
        version mismatch: the caller closes rather than guessing."""
        encoder, decoder = self._pair(hybrid=hybrid)
        # Reach past encode()'s validation to build a record no version
        # defines.
        decoder.push(encoder._emit(0x7f, b'from the future'))
        with pytest.raises(fteproxy.record_layer.UnknownRecordType):
            decoder.pop_records()

    def test_encode_rejects_an_unknown_type(self):
        encoder, _ = self._pair()
        with pytest.raises(ValueError):
            encoder.encode(0x7f, b'')

    def test_encode_rejects_an_oversized_payload(self):
        encoder, _ = self._pair(hybrid=False)
        with pytest.raises(ValueError):
            encoder.encode(fteproxy.record_layer.OPEN,
                           b'x' * (encoder.capacity + 1))

    def test_capacity_accounts_for_the_type_byte(self):
        """In format mode the type byte comes out of the covertext's fixed
        capacity. In hybrid mode the body has no fixed width, so it rides on
        top and the chunk boundaries are unchanged: a 1 MiB write is still one
        record, not one plus a one-byte straggler."""
        key = conftest.TEST_KEY
        cipher = fteproxy._make_cipher(
            fteproxy.defs.getRegex(SHAPE_FORMAT),
            fteproxy.defs.getLength(SHAPE_FORMAT), key)
        formatted = fteproxy.record_layer.Encoder(cipher=cipher)
        assert formatted.capacity == cipher.max_plaintext_bytes - 12 - 1
        body = fteproxy._make_body_cipher(key)
        hybrid = fteproxy.record_layer.Encoder(cipher=cipher, body_cipher=body)
        assert hybrid.capacity == body.max_plaintext_bytes

    def test_a_full_capacity_write_is_one_record(self):
        encoder, decoder = self._pair(hybrid=True)
        payload = b'z' * encoder.capacity
        encoder.push(payload)
        wire = encoder.pop()
        decoder.push(wire)
        assert decoder.pop_records() == [(fteproxy.record_layer.DATA, payload)]

    def test_pop_refuses_a_control_record(self):
        """pop() is the data-only convenience; a control record must not be
        silently dropped by a caller that only wanted bytes."""
        encoder, decoder = self._pair()
        decoder.push(encoder.encode(fteproxy.record_layer.OPEN, b'dest'))
        with pytest.raises(fteproxy.record_layer.UnknownRecordType):
            decoder.pop()


class TestDecoderFailsClosed:
    """A stream that fails to authenticate is closed, not buffered.

    Ports the hardening from the pre-1.0 review (was PR #235 against the old
    negotiation code) onto the 1.0 record layer: after a bad record the decoder
    fails closed, drops its buffer, and refuses further input, so a peer that
    holds the keys cannot grow the server's buffer without bound.
    """

    def _pair(self, hybrid):
        key = conftest.TEST_KEY
        regex = fteproxy.defs.getRegex(SHAPE_FORMAT)
        length = fteproxy.defs.getLength(SHAPE_FORMAT)
        cipher = fteproxy._make_cipher(regex, length, key)
        body = fteproxy._make_body_cipher(key) if hybrid else None
        enc = fteproxy.record_layer.Encoder(cipher=cipher, body_cipher=body)
        dec = fteproxy.record_layer.Decoder(cipher=cipher, body_cipher=body)
        return enc, dec

    @pytest.mark.parametrize('hybrid', [False, True])
    def test_good_then_garbage_fails_closed(self, hybrid):
        enc, dec = self._pair(hybrid)
        enc.push(b'hello')
        dec.push(enc.pop())
        assert dec.pop() == b'hello'
        assert not dec.failed
        dec.push(b'\x00' * dec._frame_size)
        assert dec.pop_records() == []
        assert dec.failed
        assert dec._buffer == b''
        with pytest.raises(fteproxy.record_layer.StreamFailedError):
            dec.push(b'more')

    @pytest.mark.parametrize('hybrid', [False, True])
    def test_good_records_before_bad_are_delivered(self, hybrid):
        enc, dec = self._pair(hybrid)
        enc.push(b'first')
        good = enc.pop()
        dec.push(good + b'\x00' * dec._frame_size)
        assert dec.pop() == b'first'
        assert dec.failed

    @pytest.mark.parametrize('hybrid', [False, True])
    def test_garbage_stream_never_accumulates(self, hybrid):
        _enc, dec = self._pair(hybrid)
        dec.push(b'\x00' * dec._frame_size)
        assert dec.pop_records() == []
        assert dec.failed
        # The buffer is dropped and further input is refused, so a flood of
        # garbage cannot grow it.
        assert len(dec._buffer) < dec.max_record_bytes
        with pytest.raises(fteproxy.record_layer.StreamFailedError):
            dec.push(b'\x00' * (16 * dec._frame_size))
