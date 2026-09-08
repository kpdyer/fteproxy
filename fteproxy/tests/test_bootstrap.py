"""Tests for the standalone permutation bootstrap codec."""

from collections import Counter
from itertools import permutations
import hashlib

import pytest

from fteproxy.bootstrap import (
    BATCH_WORDS,
    MAX_DESCRIPTION,
    MAX_WORD_BYTES,
    BootstrapError,
    Decoder,
    Multiset,
    encode,
)


KEY = hashlib.sha256(b"bootstrap test key").digest()
SCAN_BYTES = BATCH_WORDS * MAX_WORD_BYTES


def _words(width=2):
    return [index.to_bytes(width, "big") for index in range(BATCH_WORDS)]


def _decode_all(wire, key=KEY, chunk=97):
    decoder = Decoder(key)
    result = None
    for offset in range(0, len(wire), chunk):
        result = decoder.feed(wire[offset:offset + chunk])
        if result is not None:
            return result, decoder
    return result, decoder


def test_multiset_rank_unrank_exhausts_small_domains():
    for seed, width in ((b"aab", 1), (b"aabb", 1), (b"abcd", 2)):
        fmt = Multiset(seed, width)
        ordered = sorted(set(permutations(
            (seed[offset:offset + width]
             for offset in range(0, len(seed), width)))))
        expected = [b"".join(words) for words in ordered]
        assert fmt.cardinality == len(expected)
        for index, word in enumerate(expected):
            assert fmt.unrank(index) == word
            assert fmt.rank(word) == index


def test_round_trip_preserves_multiset_and_discovers_width():
    words = _words(2)
    wire = encode(KEY, words, b"selected regex")
    result, decoder = _decode_all(wire, chunk=31)
    assert result is not None
    assert result.description == b"selected regex"
    assert result.word_bytes == 2
    assert result.remainder == b""
    assert Counter(wire[offset:offset + 2]
                   for offset in range(0, len(wire), 2)) == Counter(words)
    assert result.transcript_digest == hashlib.sha256(wire).digest()
    assert decoder.attempts == 2


def test_coalesced_trailing_bytes_beyond_scan_ceiling_are_remainder():
    wire = encode(KEY, _words(2), b"description")
    trailing = b"application record" * ((SCAN_BYTES // 18) + 2)
    result = Decoder(KEY).feed(wire + trailing)
    assert result is not None
    assert result.remainder == trailing


def test_duplicate_covertexts_preserve_capacity_and_decode():
    words = _words()
    words[0] = words[1]
    wire = encode(KEY, words, b"duplicates are allowed")
    assert Counter(wire[i:i + 2] for i in range(0, len(wire), 2)) == Counter(words)
    assert Decoder(KEY).feed(wire).description == b"duplicates are allowed"


def test_fragmentation_does_not_repeat_candidate_work():
    wire = encode(KEY, _words(2), b"fragmented")
    decoder = Decoder(KEY)
    assert decoder.feed(wire[:BATCH_WORDS]) is None
    assert decoder.attempts == 1
    result = decoder.feed(wire[BATCH_WORDS:])
    assert result is not None
    assert result.word_bytes == 2
    assert decoder.attempts == 2


def test_capacity_and_input_limits_are_rejected():
    with pytest.raises(BootstrapError, match="capacity"):
        encode(KEY, [b"x"] * BATCH_WORDS, b"")
    with pytest.raises(BootstrapError, match="description"):
        encode(KEY, _words(), b"x" * (MAX_DESCRIPTION + 1))
    with pytest.raises(BootstrapError, match="exactly"):
        encode(KEY, _words()[:-1], b"")
    with pytest.raises(BootstrapError, match="scan limit"):
        Decoder(KEY).feed(b"\0" * SCAN_BYTES)


@pytest.mark.parametrize("mutate", ["order", "content"])
def test_tampering_is_not_accepted(mutate):
    wire = encode(KEY, _words(2), b"authenticated")
    if mutate == "order":
        altered = bytearray(wire)
        altered[:2], altered[2:4] = altered[2:4], altered[:2]
    else:
        altered = bytearray(wire)
        altered[0] ^= 1
    result, decoder = _decode_all(bytes(altered), chunk=len(altered))
    assert result is None
    assert decoder.attempts == 2


def test_wrong_key_is_not_accepted():
    wire = encode(KEY, _words(2), b"keyed")
    result, decoder = _decode_all(wire, key=hashlib.sha256(b"another key").digest(),
                                  chunk=len(wire))
    assert result is None
    assert decoder.attempts == 2


def test_decoder_rejects_more_data_after_success():
    wire = encode(KEY, _words(2), b"")
    result = Decoder(KEY).feed(wire)
    assert result is not None
    decoder = Decoder(KEY)
    assert decoder.feed(wire) is not None
    with pytest.raises(BootstrapError, match="already"):
        decoder.feed(b"trailing")


@pytest.mark.parametrize("key", [b"", b"short", b"x" * 31, b"x" * 33])
def test_codec_requires_a_32_byte_key(key):
    with pytest.raises(BootstrapError, match="32 bytes"):
        Decoder(key)
    with pytest.raises(BootstrapError, match="32 bytes"):
        encode(key, _words(), b"description")
