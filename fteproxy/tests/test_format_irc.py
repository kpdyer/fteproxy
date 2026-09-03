#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Format tests for the ``irc`` protocol part (phase F5).

Exercises ``fteproxy/defs/parts/irc.json`` end to end for both roles of the
symmetric IRC line grammar:

* the cipher builds and holds at least the capacity floor (128 bytes);
* random payloads round-trip through the record layer in ``format`` and
  ``hybrid`` modes;
* every sealed format-mode covertext matches the format regex, is a
  structurally valid IRC line (:func:`fteproxy.tests.realism.irc.check`), and
  the batch is free of degenerate single-byte runs (``statistical_guard``);
* the assembled definitions expose ``irc`` as a request/response base.

Runs standalone -- it binds no ports and touches no other protocol.
"""

import os
import re

import pytest

import fteproxy
import fteproxy.defs
import fteproxy.record_layer as rl
from fteproxy.tests.realism import (
    format_covertexts,
    load_part,
    statistical_guard,
)
from fteproxy.tests.realism.irc import check as irc_check

MIN_CAPACITY = 128
KEY = b'\x00' * 32
PART = load_part('irc')
ENTRIES = ('irc-request', 'irc-response')


def _cipher(regex, length):
    return fteproxy._make_cipher(regex, length, KEY)


@pytest.mark.parametrize('name', ENTRIES)
def test_part_has_expected_shape(name):
    spec = PART[name]
    assert spec['role'] == 'line'
    assert spec['mode_hint'] == 'format'
    assert spec['default'] is False
    assert spec['port'] == [6667]


@pytest.mark.parametrize('name', ENTRIES)
def test_cipher_builds_with_capacity_floor(name):
    spec = PART[name]
    capacity = _cipher(spec['regex'], spec['length']).max_plaintext_bytes
    assert capacity >= MIN_CAPACITY, (
        '%s: capacity %d below the %d-byte floor'
        % (name, capacity, MIN_CAPACITY))


@pytest.mark.parametrize('mode', ['format', 'hybrid'])
@pytest.mark.parametrize('name', ENTRIES)
def test_round_trips_through_record_layer(name, mode):
    spec = PART[name]
    regex, length = spec['regex'], spec['length']
    hybrid = (mode == 'hybrid')
    encoder = rl.Encoder(
        cipher=_cipher(regex, length),
        body_cipher=fteproxy._make_body_cipher(KEY) if hybrid else None)
    decoder = rl.Decoder(
        cipher=_cipher(regex, length),
        body_cipher=fteproxy._make_body_cipher(KEY) if hybrid else None)
    for i in range(16):
        payload = os.urandom((i * 13) % (encoder.capacity + 1))
        encoder.push(payload)
        decoder.push(encoder.pop())
        assert decoder.pop() == payload, (
            '%s: payload %d did not survive %s mode' % (name, i, mode))


@pytest.mark.parametrize('name', ENTRIES)
def test_sealed_covertexts_are_realistic_irc(name):
    spec = PART[name]
    regex, length = spec['regex'], spec['length']
    pattern = re.compile(regex.encode('latin-1'), re.DOTALL)
    covertexts = format_covertexts(regex, length, n=256)
    assert len(covertexts) == 256
    for covertext in covertexts:
        assert pattern.fullmatch(covertext), (
            '%s: sealed covertext does not match the regex: %r'
            % (name, covertext))
        irc_check(covertext)
    statistical_guard(covertexts)


def test_irc_is_a_request_response_base():
    assert 'irc' in fteproxy.defs.base_names(PART)
