#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test both DNS directions: capacity, framing, round trips, and message structure.

Handshakes use max_length; format-mode records use the allowed wire lengths.
The external two-byte prefix is excluded from regex matching. Independent
parser checks cover the modeled DNS subset, including name lengths and one
A answer. Hybrid mode round-trips but its raw tail is not DNS-over-TCP framing.
"""

import collections
import os
import re

import pytest

import fteproxy
import fteproxy.defs
import fteproxy.record_layer as rl
import fteproxy.tests.realism as realism
import fteproxy.tests.realism.dns as dns_realism


_KEY = b'\x00' * 32
_PART = realism.load_part('dns')
_NAMES = ('dns-request', 'dns-response')

# Fixed-width overhead outside QNAME: header and QTYPE/QCLASS, plus the
# answer record in replies. QNAME uses wire length minus prefix and overhead.
_NON_NAME_BYTES = {'dns-request': 16, 'dns-response': 32}
_MAX_NAME_OCTETS = 255
#: A real query name is short; the *longest* covertext is still far past this,
#: which is the limit a length range narrows rather than removes.
_TYPICAL_NAME_OCTETS = 40

_PREFIX_LEN = fteproxy.defs.LENGTH_PREFIX_BYTES


def _spec(name):
    return _PART[name]


def _cipher(name):
    spec = _spec(name)
    return fteproxy._spec_cipher(spec, fteproxy.defs.spec_length(spec), _KEY)


@pytest.mark.parametrize('name', _NAMES)
def test_cipher_builds_with_capacity_floor(name):
    """At ``max_length``, where the handshake seals."""
    capacity = _cipher(name).max_plaintext_bytes
    assert capacity >= 128
    assert capacity >= fteproxy.defs.MIN_CAPACITY


@pytest.mark.parametrize('name', _NAMES)
def test_schema_v2_keys(name):
    spec = _spec(name)
    assert fteproxy.defs.spec_port(spec) == [53]
    assert fteproxy.defs.spec_mode_hint(spec) == fteproxy.defs.MODE_FORMAT
    assert fteproxy.defs.spec_is_default(spec) is False
    assert fteproxy.defs.spec_description(spec)
    expected_role = (fteproxy.defs.ROLE_REQUEST if name.endswith('-request')
                     else fteproxy.defs.ROLE_RESPONSE)
    assert fteproxy.defs.spec_role(name, spec) == expected_role


@pytest.mark.parametrize('name', _NAMES)
def test_the_fragment_declares_length_prefix_framing(name):
    """The prefix is framing, so it is a schema key and not a regex literal."""
    spec = _spec(name)
    assert fteproxy.defs.spec_framing(spec) == \
        fteproxy.defs.FRAMING_LENGTH_PREFIX
    assert fteproxy.defs.spec_is_variable(spec)
    assert fteproxy.defs.spec_terminator(spec) is None
    assert 'length' not in spec
    assert spec['max_length'] == 272
    assert fteproxy.defs.spec_length(spec) == 272
    # The regex describes the message alone: it opens at the DNS header's
    # ID field, not at the two-byte length literal it used to carry.
    assert spec['regex'].startswith('^[\x00-\xff][\x00-\xff]')


@pytest.mark.parametrize('name', _NAMES)
@pytest.mark.parametrize('hybrid', [False, True])
def test_round_trip_through_record_layer(name, hybrid):
    spec = _spec(name)
    encoder, decoder = realism.record_layer_pair(spec, hybrid=hybrid, key=_KEY)
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
    allowed = fteproxy.defs.spec_allowed_lengths(spec)

    covertexts = realism.format_covertexts(spec, n=256)
    assert len(covertexts) == 256
    for covertext in covertexts:
        assert len(covertext) in allowed
        # The prefix is framing; the regex describes what follows it.
        assert int.from_bytes(covertext[:_PREFIX_LEN], 'big') == \
            len(covertext) - _PREFIX_LEN
        assert pattern.fullmatch(covertext[_PREFIX_LEN:]), covertext[:32]
        dns_realism.check(covertext)
    realism.statistical_guard(covertexts)


@pytest.mark.parametrize('name', _NAMES)
def test_sealed_covertexts_carry_the_expected_message_shape(name):
    """The parser sees the direction, framing and record the format promises."""
    spec = _spec(name)
    covertexts = realism.format_covertexts(spec, n=32)
    is_response = name.endswith('-response')
    for covertext in covertexts:
        # RFC 1035 4.2.2 framing: the prefix accounts for every following byte.
        assert int.from_bytes(covertext[:2], 'big') == len(covertext) - 2
        message = dns_realism.parse(covertext)
        assert message.is_response is is_response
        assert message.qclass == 1
        if is_response:
            assert message.qtype == 1                  # A, matching the answer
            assert message.address is not None
            assert 0 <= message.ttl <= 604800
        else:
            assert message.qtype in (1, 28)            # A or AAAA


@pytest.mark.parametrize('name', _NAMES)
def test_the_question_name_varies_with_the_covertext_length(name):
    """Each wire length yields a corresponding encoded QNAME length within 255 bytes."""
    spec = _spec(name)
    allowed = fteproxy.defs.spec_allowed_lengths(spec)
    expected = {length - _PREFIX_LEN - _NON_NAME_BYTES[name]
                for length in allowed}

    covertexts = realism.format_covertexts(spec, n=256)
    seen = collections.Counter()
    for covertext in covertexts:
        message = dns_realism.parse(covertext)
        assert message.name_octets == \
            len(covertext) - _PREFIX_LEN - _NON_NAME_BYTES[name]
        assert message.name_octets <= _MAX_NAME_OCTETS
        seen[message.name_octets] += 1

    assert set(seen) <= expected
    assert len(seen) >= 6, seen
    assert max(seen) == max(expected)

    # Small payloads should exercise the shortest allowed question name.
    encoder, _decoder = realism.record_layer_pair(spec, key=_KEY)
    wire = b''
    for _ in range(200):
        encoder.push(b'x')
        wire += encoder.pop()
    shortest = min(dns_realism.parse(covertext).name_octets
                   for covertext in realism.frame_wire(wire, spec))
    assert shortest == min(expected)
    assert shortest < _TYPICAL_NAME_OCTETS * 2


@pytest.mark.parametrize('name', _NAMES)
def test_every_allowed_length_carries_a_data_record(name):
    """Every allowed length holds a 12-byte seal, a type byte, and at least one payload byte."""
    spec = _spec(name)
    variable = fteproxy._variable_lengths_for_spec(spec, _KEY)
    assert variable.min_length == spec['min_length']
    assert variable.max_length == spec['max_length']
    assert min(variable.capacities.values()) >= 1

    floor = rl._SEAL_OVERHEAD + rl._TYPE_LEN + 1
    for length in variable.lengths:
        assert variable.cipher(length).max_plaintext_bytes >= floor, length


def test_the_short_end_is_set_by_capacity_and_by_the_reply():
    """The reply's smaller capacity sets the shared minimum above the grammar's shortest message."""
    minimum = _spec('dns-request')['min_length']
    assert _spec('dns-response')['min_length'] == minimum

    floor = rl._SEAL_OVERHEAD + rl._TYPE_LEN + 1
    request = fteproxy._spec_cipher(_spec('dns-request'), minimum, _KEY)
    response = fteproxy._spec_cipher(_spec('dns-response'), minimum, _KEY)
    assert response.max_plaintext_bytes < request.max_plaintext_bytes
    assert response.max_plaintext_bytes >= floor

    starved = fteproxy._spec_cipher(_spec('dns-response'), 80, _KEY)
    assert starved.max_plaintext_bytes < floor, (
        'the reply carries a record at 80 wire bytes; lower min_length rather '
        'than leaving realism on the table')


def test_realism_check_rejects_malformed_messages():
    """The independent parser rejects malformed examples."""
    spec = _spec('dns-request')
    covertext = realism.format_covertexts(spec, n=1)[0]
    dns_realism.check(covertext)  # the unmodified covertext passes

    def mutate(index, value):
        broken = bytearray(covertext)
        broken[index] = value
        return bytes(broken)

    # A length prefix that disagrees with the message.
    with pytest.raises(dns_realism.DNSRealismError):
        dns_realism.check(covertext[:-1])
    # Flags that are not a standard query.
    with pytest.raises(dns_realism.DNSRealismError):
        dns_realism.check(mutate(4, 0x40))
    # A section count the shape does not carry (ANCOUNT on a query).
    with pytest.raises(dns_realism.DNSRealismError):
        dns_realism.check(mutate(9, 0x01))
    # A label length byte that no longer matches its label.
    with pytest.raises(dns_realism.DNSRealismError):
        dns_realism.check(mutate(14, 0x3f))
    # A non-LDH byte inside a label.
    with pytest.raises(dns_realism.DNSRealismError):
        dns_realism.check(mutate(15, 0x00))
    # A QCLASS that is not IN.
    with pytest.raises(dns_realism.DNSRealismError):
        dns_realism.check(mutate(len(covertext) - 1, 0x05))
    # Not bytes at all.
    with pytest.raises(TypeError):
        dns_realism.check('not bytes')


def test_base_name_present():
    assert 'dns' in fteproxy.defs.base_names(_PART)
