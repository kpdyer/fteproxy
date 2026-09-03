#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the ``ftp`` control-channel format (phase F-ftp).

Exercises the two ``parts/ftp.json`` entries end to end: the cipher builds and
clears the capacity floor, random payloads round-trip through the record layer
in both ``format`` and ``hybrid`` modes, and every sealed format-mode covertext
is a real FTP line -- it fullmatches the sampling regex, passes the independent
realism grammar check, and the batch survives the statistical guard.

Note on message-type variety: FTP puts its discriminating token (the verb or
reply code) first, so uniform rank sampling of a fixed-length format lands every
covertext in a single lexicographic branch (``CWD`` commands, ``150`` replies).
This is the seal-padding limitation documented in ``docs/format-authoring.md``
(realistic value content and length distribution are not reachable by uniform
rank sampling); the regex and the realism check still model every command and
reply the format supports.
"""

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
import fteproxy.tests.realism.ftp as ftp_realism


_KEY = b'\x00' * 32

_PART = load_part('ftp')
_ENTRIES = ('ftp-request', 'ftp-response')


def _spec(name):
    return _PART[name]


@pytest.mark.parametrize('name', _ENTRIES)
def test_cipher_builds_and_clears_capacity_floor(name):
    spec = _spec(name)
    cipher = fteproxy._make_cipher(spec['regex'], spec['length'], _KEY)
    assert cipher.max_plaintext_bytes >= fteproxy.defs.MIN_CAPACITY
    assert cipher.max_plaintext_bytes >= 128


@pytest.mark.parametrize('name', _ENTRIES)
@pytest.mark.parametrize('hybrid', [False, True], ids=['format', 'hybrid'])
def test_roundtrip_through_record_layer(name, hybrid):
    spec = _spec(name)
    regex, length = spec['regex'], spec['length']

    def make_encoder():
        return rl.Encoder(
            cipher=fteproxy._make_cipher(regex, length, _KEY),
            body_cipher=fteproxy._make_body_cipher(_KEY) if hybrid else None)

    def make_decoder():
        return rl.Decoder(
            cipher=fteproxy._make_cipher(regex, length, _KEY),
            body_cipher=fteproxy._make_body_cipher(_KEY) if hybrid else None)

    encoder, decoder = make_encoder(), make_decoder()
    import os
    for i in range(16):
        payload = os.urandom((i * 11) % (encoder.capacity + 1))
        encoder.push(payload)
        wire = encoder.pop()
        decoder.push(wire)
        assert decoder.pop() == payload


@pytest.mark.parametrize('name', _ENTRIES)
def test_sealed_covertexts_are_real_ftp(name):
    spec = _spec(name)
    regex, length = spec['regex'], spec['length']
    pattern = re.compile(regex.encode('latin-1'), re.DOTALL)

    covertexts = format_covertexts(regex, length, n=256)
    assert len(covertexts) == 256

    for covertext in covertexts:
        assert pattern.fullmatch(covertext), covertext[:64]
        ftp_realism.check(covertext)  # raises if not a valid FTP line

    statistical_guard(covertexts)


def test_realism_check_rejects_non_ftp():
    # A few negatives to prove the grammar check is not vacuous.
    for bad in (
        b'CWD /var/log',                 # missing CRLF
        b'CWD \r\n',                     # empty argument
        b'CWD /a /b\r\n',                # argument with a space
        b'HELO world\r\n',               # unknown verb
        b'PASV now\r\n',                 # bare verb given an argument
        b'TYPE Q\r\n',                   # bad TYPE code
        b'999 nope\r\n',                 # unknown reply code
        b'220\r\n',                      # reply with no text
        b'220  \r\n'.replace(b' ', b'\x01'),  # control byte in text
        b'CWD /a\r\nCWD /b\r\n',         # two lines
    ):
        with pytest.raises(ftp_realism.FTPRealismError):
            ftp_realism.check(bad)


def test_base_name_present():
    assert 'ftp' in fteproxy.defs.base_names(load_part('ftp'))
