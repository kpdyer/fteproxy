#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Format tests for the ``http`` protocol (phase F1).

For both ``http-request`` and ``http-response``:

* the libfte cipher builds and holds at least :data:`fteproxy.defs.MIN_CAPACITY`
  bytes of capacity;
* random payloads round-trip through the record layer in both ``format`` and
  ``hybrid`` modes (``http`` is a ``hybrid`` format, so either mode may be
  selected at connection time);
* a batch of sealed **format-mode** covertexts each fully match the regex, pass
  the independent-parser realism :func:`~fteproxy.tests.realism.http.check`, and
  clear :func:`~fteproxy.tests.realism.statistical_guard`;
* the base name ``http`` is exposed by :func:`fteproxy.defs.base_names`.

``http`` is variable length (phase F7): a format-mode record picks one of the
lengths in ``[min_length, max_length]``, so these tests read the length from
:func:`fteproxy.defs.spec_length` (the ``max_length`` the handshake seals at)
and check a covertext's length against the allowed set rather than against one
number. ``fteproxy/tests/test_variable_length.py`` covers the framing itself.
"""

import os
import re

import pytest

import fteproxy
import fteproxy.defs
import fteproxy.record_layer
import fteproxy.tests.realism as realism
import fteproxy.tests.realism.http as http_realism


_KEY = b'\x00' * 32
_PART = realism.load_part('http')
_NAMES = ('http-request', 'http-response')


def _spec(name):
    return _PART[name]


def _cipher(name):
    spec = _spec(name)
    return fteproxy._make_cipher(
        spec['regex'], fteproxy.defs.spec_length(spec), _KEY)


@pytest.mark.parametrize('name', _NAMES)
def test_cipher_builds_with_capacity_floor(name):
    capacity = _cipher(name).max_plaintext_bytes
    assert capacity >= 128
    assert capacity >= fteproxy.defs.MIN_CAPACITY


@pytest.mark.parametrize('name', _NAMES)
def test_hybrid_uses_a_chunked_header_without_changing_the_handshake(name):
    spec = _spec(name)
    assert fteproxy.defs.spec_hybrid_framing(spec) == \
        fteproxy.defs.HYBRID_FRAMING_HTTP_CHUNKED
    assert 'Transfer-Encoding: chunked\r\n' in \
        fteproxy.defs.spec_hybrid_regex(spec)
    assert 'Transfer-Encoding: chunked\r\n' not in spec['regex']


@pytest.mark.parametrize('name', _NAMES)
@pytest.mark.parametrize('hybrid', [False, True])
def test_round_trip_through_record_layer(name, hybrid):
    encoder, decoder = realism.record_layer_pair(_spec(name), hybrid=hybrid,
                                                 key=_KEY)
    for i in range(16):
        payload = os.urandom((i * 11) % (encoder.capacity + 1))
        encoder.push(payload)
        wire = encoder.pop()
        decoder.push(wire)
        assert decoder.pop() == payload


@pytest.mark.parametrize('name', _NAMES)
def test_hybrid_record_is_one_complete_chunked_http_message(name):
    """The parser sees the encrypted carrier as the declared HTTP body.

    This is the regression for the old layout, where the request declared no
    body and the response declared ``Content-Length: 0`` before the record
    layer appended ciphertext anyway.  Exercise the real FTE header, body AEAD,
    HTTP parser and record decoder together in both directions.
    """
    spec = _spec(name)
    encoder, decoder = realism.record_layer_pair(spec, hybrid=True, key=_KEY)
    payload = b'full HTTP message, then full fteproxy record'
    wire = encoder.encode(fteproxy.record_layer.DATA, payload)

    framed_ciphertext = http_realism.parse_hybrid_message(wire)
    assert len(framed_ciphertext) > len(payload)
    assert b'Transfer-Encoding: chunked\r\n' in \
        wire[:fteproxy.hybrid_header_length(spec)]

    decoder.push(wire)
    assert decoder.pop_records() == [(fteproxy.record_layer.DATA, payload)]
    assert not decoder.failed


@pytest.mark.parametrize('name', _NAMES)
def test_hybrid_decoder_rejects_broken_http_chunk_terminator(name):
    spec = _spec(name)
    encoder, decoder = realism.record_layer_pair(spec, hybrid=True, key=_KEY)
    wire = encoder.encode(fteproxy.record_layer.DATA, b'payload')
    assert wire.endswith(b'\r\n0\r\n\r\n')

    decoder.push(wire[:-1] + b'X')
    assert decoder.pop_records() == []
    assert decoder.failed


@pytest.mark.parametrize('name', _NAMES)
def test_sealed_covertexts_are_realistic(name):
    spec = _spec(name)
    pattern = re.compile(spec['regex'].encode('latin-1'), re.DOTALL)
    allowed = realism.allowed_lengths(spec)

    covertexts = realism.format_covertexts(spec, n=256)
    assert len(covertexts) == 256
    for covertext in covertexts:
        assert len(covertext) in allowed
        assert pattern.fullmatch(covertext), covertext[:80]
        http_realism.check(covertext)
    realism.statistical_guard(covertexts)


def test_base_name_present():
    assert 'http' in fteproxy.defs.base_names(_PART)
