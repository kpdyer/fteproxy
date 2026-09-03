#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Format tests for the ``smtp`` covertext format (phase F5).

Exercises both ``smtp-request`` and ``smtp-response`` end to end: the libfte
cipher builds and clears the capacity floor, random payloads round-trip through
the record layer in both ``format`` and ``hybrid`` modes, and a batch of sealed
format-mode covertexts is drawn through the real record layer and judged for
realism (regex fullmatch, the SMTP grammar :func:`~fteproxy.tests.realism.smtp.check`,
and the statistical guard against degenerate single-byte runs).

``smtp`` is variable length (phase F7): a format-mode record picks one of the
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
from fteproxy.tests.realism import (
    allowed_lengths,
    format_covertexts,
    load_part,
    record_layer_pair,
    statistical_guard,
)
from fteproxy.tests.realism import smtp as smtp_realism

_KEY = b'\x00' * 32
_PART = load_part('smtp')
_ROLES = ('smtp-request', 'smtp-response')


def _spec(name):
    return _PART[name]


@pytest.mark.parametrize('name', _ROLES)
def test_cipher_builds_and_meets_capacity_floor(name):
    spec = _spec(name)
    cipher = fteproxy._make_cipher(
        spec['regex'], fteproxy.defs.spec_length(spec), _KEY)
    assert cipher.max_plaintext_bytes >= 128
    assert cipher.max_plaintext_bytes >= fteproxy.defs.MIN_CAPACITY


@pytest.mark.parametrize('name', _ROLES)
@pytest.mark.parametrize('hybrid', [False, True], ids=['format', 'hybrid'])
def test_round_trip_through_record_layer(name, hybrid):
    encoder, decoder = record_layer_pair(_spec(name), hybrid=hybrid, key=_KEY)
    for i in range(16):
        payload = os.urandom((i * 5) % (encoder.capacity + 1))
        encoder.push(payload)
        wire = encoder.pop()
        decoder.push(wire)
        assert decoder.pop() == payload


@pytest.mark.parametrize('name', _ROLES)
def test_format_covertexts_are_realistic(name):
    spec = _spec(name)
    pattern = re.compile(spec['regex'].encode('latin-1'), re.DOTALL)
    allowed = allowed_lengths(spec)

    covertexts = format_covertexts(spec, n=256)
    assert len(covertexts) == 256
    for covertext in covertexts:
        assert len(covertext) in allowed
        assert pattern.fullmatch(covertext), repr(covertext[:64])
        smtp_realism.check(covertext)
    statistical_guard(covertexts)


def test_realism_check_rejects_non_smtp():
    # A structurally wrong line must be rejected, proving the grammar check is
    # doing more than accepting anything with a CRLF.
    with pytest.raises(smtp_realism.SMTPRealismError):
        smtp_realism.check(b'GET / HTTP/1.1\r\n')
    with pytest.raises(smtp_realism.SMTPRealismError):
        smtp_realism.check(b'EHLO example.com')  # no CRLF
    with pytest.raises(smtp_realism.SMTPRealismError):
        smtp_realism.check(b'999 bogus code\r\n')


def test_base_name_present():
    assert 'smtp' in fteproxy.defs.base_names(load_part('smtp'))
