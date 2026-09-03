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
