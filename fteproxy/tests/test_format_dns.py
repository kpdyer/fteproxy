#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Format tests for the ``dns`` protocol.

``dns`` is the release's one binary format: a covertext is a DNS message framed
for TCP the way RFC 1035 section 4.2.2 frames it -- a two-byte big-endian length
prefix, then that many bytes of message. Everything the other formats express as
text this one expresses as bytes, so the fragment's regex is written with
literal ``\\u00XX`` characters and literal-character classes, and the realism
judgement is a hand-written parser
(:mod:`fteproxy.tests.realism.dns`) rather than a borrowed stdlib one.

For both ``dns-request`` and ``dns-response``:

* the libfte cipher builds and holds at least :data:`fteproxy.defs.MIN_CAPACITY`
  bytes of capacity;
* random payloads round-trip through the record layer in both ``format`` and
  ``hybrid`` modes (``dns`` is a ``format`` format -- see below -- but the
  client's ``--mode`` can still select ``hybrid``, so both must work);
* a batch of sealed **format-mode** covertexts each fully match the regex, pass
  the independent-parser realism :func:`~fteproxy.tests.realism.dns.check`, and
  clear :func:`~fteproxy.tests.realism.statistical_guard`;
* the base name ``dns`` is exposed by :func:`fteproxy.defs.base_names`.

Why ``mode_hint`` is ``format``
-------------------------------

A DNS message is self-delimiting: its length prefix says exactly how many bytes
follow. ``hybrid`` mode would put a raw high-entropy body immediately after the
formatted covertext, so the bytes on the wire would be a valid DNS message
followed by a tail the prefix does not account for -- visible to anything that
reads DNS-over-TCP framing at all. Every byte therefore has to go through the
format.

The fixed-length limitation this format makes vivid (phase F7)
--------------------------------------------------------------

Every covertext is exactly ``length`` bytes, and a DNS query has almost nowhere
to absorb slack: the header is 12 fixed bytes and the question trailer is 4
more, so the padding all lands in QNAME. At length 272 the encoded question name
is 254 octets in a query and 238 in a reply. That is *inside* RFC 1035's
255-octet ceiling -- deliberately, since a longer name is not merely unusual but
malformed, and :mod:`~fteproxy.tests.realism.dns` enforces the ceiling -- but it
is still far longer than a real query name, which is typically 20 to 40 octets.
:func:`test_fixed_length_pads_the_question_name` asserts that shape rather than
leaving it as a comment: a fixed length buys a valid message, not a typical one,
and closing that gap is what variable-length covertexts (F7) are for.
"""

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

#: Encoded question-name length each direction pads to at the fragment's length,
#: and the RFC 1035 ceiling it stays under.
_NAME_OCTETS = {'dns-request': 254, 'dns-response': 238}
_MAX_NAME_OCTETS = 255
#: A real query name is short; anything past this is the fixed-length artifact
#: the module docstring describes.
_TYPICAL_NAME_OCTETS = 40


def _spec(name):
    return _PART[name]


def _cipher(name):
    spec = _spec(name)
    return fteproxy._make_cipher(spec['regex'], spec['length'], _KEY)


@pytest.mark.parametrize('name', _NAMES)
def test_cipher_builds_with_capacity_floor(name):
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
@pytest.mark.parametrize('hybrid', [False, True])
def test_round_trip_through_record_layer(name, hybrid):
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

    encoder = make_encoder()
    decoder = make_decoder()
    for i in range(16):
        payload = os.urandom((i * 11) % (encoder.capacity + 1))
        encoder.push(payload)
        wire = encoder.pop()
        decoder.push(wire)
        assert decoder.pop() == payload


@pytest.mark.parametrize('name', _NAMES)
def test_sealed_covertexts_are_realistic(name):
    spec = _spec(name)
    regex, length = spec['regex'], spec['length']
    pattern = re.compile(regex.encode('latin-1'), re.DOTALL)

    covertexts = realism.format_covertexts(regex, length, n=256)
    assert len(covertexts) == 256
    for covertext in covertexts:
        assert len(covertext) == length
        assert pattern.fullmatch(covertext), covertext[:32]
        dns_realism.check(covertext)
    realism.statistical_guard(covertexts)


@pytest.mark.parametrize('name', _NAMES)
def test_sealed_covertexts_carry_the_expected_message_shape(name):
    """The parser sees the direction, framing and record the format promises."""
    spec = _spec(name)
    covertexts = realism.format_covertexts(spec['regex'], spec['length'], n=32)
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
def test_fixed_length_pads_the_question_name(name):
    """A fixed covertext length lands entirely in QNAME.

    The header and the question trailer are fixed-width, so the only field that
    can absorb the padding is the name. It stays inside RFC 1035's 255-octet
    ceiling -- a longer name would be malformed, not merely odd -- but it is
    several times a typical query name. This is the clearest case in the release
    for variable-length covertexts (F7); until then the limitation is asserted
    here rather than left implicit.
    """
    spec = _spec(name)
    covertexts = realism.format_covertexts(spec['regex'], spec['length'], n=32)
    for covertext in covertexts:
        message = dns_realism.parse(covertext)
        assert message.name_octets == _NAME_OCTETS[name]
        assert message.name_octets <= _MAX_NAME_OCTETS
        assert message.name_octets > _TYPICAL_NAME_OCTETS


def test_realism_check_rejects_malformed_messages():
    """The judge is strict enough to be worth passing."""
    spec = _spec('dns-request')
    covertext = realism.format_covertexts(spec['regex'], spec['length'], n=1)[0]
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
