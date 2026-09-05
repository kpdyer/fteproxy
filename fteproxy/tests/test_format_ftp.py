#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test FTP capacity and record round trips in format and hybrid modes.

Sample sealed format-mode covertexts and check regex membership, the modeled
FTP line subset, and same-byte runs. Sampling does not prove realistic verb
frequencies, reply ordering, or a complete FTP conversation.
"""

import os
import re

import pytest

import fteproxy
import fteproxy.defs
from fteproxy.tests.realism import (
    allowed_lengths,
    format_covertexts,
    record_layer_pair,
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
    cipher = fteproxy._make_cipher(
        spec['regex'], fteproxy.defs.spec_length(spec), _KEY)
    assert cipher.max_plaintext_bytes >= fteproxy.defs.MIN_CAPACITY
    assert cipher.max_plaintext_bytes >= 128


@pytest.mark.parametrize('name', _ENTRIES)
@pytest.mark.parametrize('hybrid', [False, True], ids=['format', 'hybrid'])
def test_roundtrip_through_record_layer(name, hybrid):
    encoder, decoder = record_layer_pair(_spec(name), hybrid=hybrid, key=_KEY)
    for i in range(16):
        payload = os.urandom((i * 11) % (encoder.capacity + 1))
        encoder.push(payload)
        wire = encoder.pop()
        decoder.push(wire)
        assert decoder.pop() == payload


@pytest.mark.parametrize('name', _ENTRIES)
def test_sealed_covertexts_are_real_ftp(name):
    spec = _spec(name)
    pattern = re.compile(spec['regex'].encode('latin-1'), re.DOTALL)
    allowed = allowed_lengths(spec)

    covertexts = format_covertexts(spec, n=256)
    assert len(covertexts) == 256

    for covertext in covertexts:
        assert len(covertext) in allowed
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
