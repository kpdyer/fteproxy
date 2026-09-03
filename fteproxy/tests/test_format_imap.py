#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Format tests for the ``imap`` protocol (phase F4).

For both ``imap-request`` and ``imap-response`` this proves the cipher builds
with capacity to spare, that random payloads round-trip through the record layer
in both ``format`` and ``hybrid`` modes, and that every sealed format-mode
covertext is a real IMAP line -- it fullmatches the format regex, passes the
independent structural :func:`fteproxy.tests.realism.imap.check`, and the batch
clears :func:`fteproxy.tests.realism.statistical_guard`.
"""

import os
import re

import pytest

import fteproxy
import fteproxy.defs
import fteproxy.record_layer as rl
from fteproxy.tests.realism import (
    format_covertexts,
    statistical_guard,
    load_part,
)
from fteproxy.tests.realism import imap as imap_realism

_KEY = b'\x00' * 32
_PART = load_part('imap')
_NAMES = ('imap-request', 'imap-response')


def _spec(name):
    return _PART[name]


@pytest.mark.parametrize('name', _NAMES)
def test_builds_with_capacity(name):
    spec = _spec(name)
    cipher = fteproxy._make_cipher(spec['regex'], spec['length'], _KEY)
    assert cipher.max_plaintext_bytes >= fteproxy.defs.MIN_CAPACITY
    assert cipher.max_plaintext_bytes >= 128


@pytest.mark.parametrize('mode', ('format', 'hybrid'))
@pytest.mark.parametrize('name', _NAMES)
def test_round_trip(name, mode):
    spec = _spec(name)
    regex, length = spec['regex'], spec['length']
    hybrid = (mode == 'hybrid')

    def encoder():
        return rl.Encoder(
            cipher=fteproxy._make_cipher(regex, length, _KEY),
            body_cipher=fteproxy._make_body_cipher(_KEY) if hybrid else None)

    def decoder():
        return rl.Decoder(
            cipher=fteproxy._make_cipher(regex, length, _KEY),
            body_cipher=fteproxy._make_body_cipher(_KEY) if hybrid else None)

    enc, dec = encoder(), decoder()
    cap = enc.capacity
    for i in range(16):
        payload = os.urandom((i * 37) % (cap + 1))
        enc.push(payload)
        dec.push(enc.pop())
        assert dec.pop() == payload


@pytest.mark.parametrize('name', _NAMES)
def test_covertexts_are_realistic(name):
    spec = _spec(name)
    regex, length = spec['regex'], spec['length']
    pattern = re.compile(regex.encode('latin-1'), re.DOTALL)

    covertexts = format_covertexts(regex, length, n=256)
    assert len(covertexts) == 256
    for covertext in covertexts:
        assert pattern.fullmatch(covertext), covertext
        imap_realism.check(covertext)
    statistical_guard(covertexts)


def test_realism_check_rejects_non_imap():
    for bad in (
        b'not imap at all\r\n',
        b'a1 FROBNICATE inbox\r\n',
        b'a1 LOGIN user\r\n',            # LOGIN missing password
        b'* 12 EXPUNGE\r\n',            # unknown counter
        b'a1 OK done',                  # no CRLF terminator
        b'a1 LOGIN u\r\np\r\n',         # embedded CRLF
        b'LOGOUT\r\n',                  # no tag
    ):
        with pytest.raises(Exception):
            imap_realism.check(bad)


def test_base_name_present():
    assert 'imap' in fteproxy.defs.base_names(load_part('imap'))
