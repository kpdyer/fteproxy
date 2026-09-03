#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Format tests for the ``sip`` protocol.

For both ``sip-request`` and ``sip-response``:

* the libfte cipher builds and holds at least :data:`fteproxy.defs.MIN_CAPACITY`
  bytes of capacity;
* random payloads round-trip through the record layer in both ``format`` and
  ``hybrid`` modes -- ``sip`` is a ``format`` protocol (a SIP body is SDP text,
  which a raw high-entropy ``hybrid`` tail would not resemble), but the client's
  ``--mode`` can still select ``hybrid``, so both must carry traffic;
* a batch of sealed **format-mode** covertexts each fully match the regex, pass
  the independent-parser realism :func:`~fteproxy.tests.realism.sip.check`, and
  clear :func:`~fteproxy.tests.realism.statistical_guard`;
* the base name ``sip`` is exposed by :func:`fteproxy.defs.base_names`.

``sip`` is variable length (phase F7): a format-mode record picks one of the
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
import fteproxy.tests.realism.sip as sip_realism


_KEY = b'\x00' * 32
_PART = realism.load_part('sip')
_NAMES = ('sip-request', 'sip-response')


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
def test_schema_v2_keys(name):
    spec = _spec(name)
    assert spec['port'] == [5060]
    assert spec['mode_hint'] == fteproxy.defs.MODE_FORMAT
    assert spec['default'] is False
    assert spec['description']
    assert fteproxy.defs.spec_role(name, spec) == (
        fteproxy.defs.ROLE_REQUEST if name.endswith('-request')
        else fteproxy.defs.ROLE_RESPONSE)


@pytest.mark.parametrize('name', _NAMES)
@pytest.mark.parametrize('hybrid', [False, True])
def test_round_trip_through_record_layer(name, hybrid):
    encoder, decoder = realism.record_layer_pair(_spec(name), hybrid=hybrid,
                                                 key=_KEY)
    for i in range(16):
        payload = os.urandom((i * 13) % (encoder.capacity + 1))
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
        sip_realism.check(covertext)
    realism.statistical_guard(covertexts)


def test_realism_check_rejects_a_non_sip_covertext():
    """The check is a real filter, not a rubber stamp."""
    valid = (b'INVITE sip:alice@example.com SIP/2.0\r\n'
             b'Via: SIP/2.0/TCP proxy.example.com;branch=z9hG4bKnashds8\r\n'
             b'From: <sip:bob@example.com>;tag=1928301774\r\n'
             b'To: <sip:alice@example.com>\r\n'
             b'Call-ID: a84b4c76e66710@pc33.example.com\r\n'
             b'CSeq: 314159 INVITE\r\n'
             b'Content-Length: 0\r\n\r\n')
    sip_realism.check(valid)

    rejects = [
        b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',   # not SIP at all
        valid.replace(b'INVITE sip:', b'SUBSCRIBE sip:', 1),  # unknown method
        valid.replace(b'SIP/2.0\r\nVia', b'SIP/1.0\r\nVia', 1),  # bad version
        valid.replace(b'Call-ID: a84b4c76e66710@pc33.example.com\r\n', b''),
        valid.replace(b'branch=z9hG4bK', b'branch=', 1),  # no magic cookie
        valid.replace(b'CSeq: 314159 INVITE', b'CSeq: xyz INVITE', 1),
        valid.replace(b'\r\n\r\n', b'\r\n'),              # unterminated headers
    ]
    for bad in rejects:
        with pytest.raises(Exception):
            sip_realism.check(bad)


def test_base_name_present():
    assert 'sip' in fteproxy.defs.base_names(_PART)
