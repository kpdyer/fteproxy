#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Variable-length covertexts (phases F7 and F7b).

Until F7 every covertext of a format was exactly one length, which SECURITY.md
called out as its own fingerprint: a length-distribution test separates a tunnel
from real traffic without looking at a single byte. Every shipped format now
picks a covertext length per format-mode record from a small set spanning
``[min_length, max_length]``, and the decoder frames the wire on that format's
delimiter instead of on a fixed slice.

There are two delimiters, and both are exercised here:

* the four text formats (``http``, ``ftp``, ``smtp``, ``sip``) end each
  covertext with a **terminator** their language cannot produce anywhere else
  (F7);
* ``dns`` carries a two-byte big-endian **length prefix** in front of each
  covertext (F7b). That prefix is what RFC 1035 section 4.2.2 says DNS over TCP
  is, and until F7b it was a literal at the head of the regex -- which is
  exactly why ``dns`` was the one format F7 had to leave fixed: a second
  covertext length would have needed a second literal, hence a second regex.
  Lifting it out of the pattern and into the record layer
  (``fteproxy.defs.FRAMING_LENGTH_PREFIX``) is what let one pattern serve all
  eight lengths.

What these tests pin down:

* the **length set** both ends derive from the definitions, without negotiating it;
* **framing**, for both delimiters: a record delivered in fragments -- including
  every split inside the terminator, and every split across a length prefix and
  a message boundary -- reassembles; a length the format does not emit, a
  corrupted covertext, a truncated message, and a peer that never sends a
  terminator each fail the stream closed rather than being buffered or guessed
  at;
* the **spread**: a stream of small and large writes produces many distinct
  covertext lengths and no dominant one, which is the point of the change, and
  for ``dns`` every covertext in that spread is still a message its independent
  realism parser accepts;
* **terminator uniqueness**, the property terminator framing rests on, including
  that the pre-F7 ``http-response`` regex (which absorbed a body and so could
  carry a CRLF CRLF inside a covertext) is rejected by the check;
* what did **not** change: the two handshake records and a ``hybrid`` header are
  still one fixed ``max_length`` covertext, the four text formats' fragments are
  byte for byte what F7 shipped, and the shape catalog is still fixed length.
"""

import collections
import os
import re
import socket
import threading

import pytest

import fteproxy
import fteproxy.conf
import fteproxy.defs
import fteproxy.defs.validate as validate
import fteproxy.handshake
import fteproxy.record_layer as rl
import fteproxy.tests.realism as realism
import fteproxy.tests.realism.dns as dns_realism


_KEY = bytes(range(32))

#: Every variable-length format the 20260903 release ships, mapped to the
#: terminator it is framed on -- or to ``None`` for the two that are framed on a
#: length prefix instead, which have no terminator at all.
VARIABLE = {
    'http-request': b'\r\n\r\n',
    'http-response': b'\r\n\r\n',
    'ftp-request': b'\r\n',
    'ftp-response': b'\r\n',
    'smtp-request': b'\r\n',
    'smtp-response': b'\r\n',
    'sip-request': b'\r\n\r\n',
    'sip-response': b'\r\n\r\n',
    'dns-request': None,
    'dns-response': None,
}

#: The subset framed on a terminator: the tests that are *about* terminators.
TERMINATED = {name: terminator for name, terminator in VARIABLE.items()
              if terminator is not None}

#: The subset framed on a length prefix.
PREFIXED = tuple(sorted(name for name, terminator in VARIABLE.items()
                        if terminator is None))

SERVER_PRIVATE, SERVER_PUBLIC = fteproxy.generate_server_key()


@pytest.fixture(autouse=True)
def _release():
    """The shipped release, restored afterwards (one test selects another)."""
    previous = fteproxy.conf.getValue('fteproxy.defs.release')
    saved = fteproxy.defs._definitions
    fteproxy.conf.setValue('fteproxy.defs.release', '20260903')
    fteproxy.defs._definitions = None
    fteproxy.defs.load_definitions()
    yield
    fteproxy.conf.setValue('fteproxy.defs.release', previous)
    fteproxy.defs._definitions = saved


def _spec(name):
    return fteproxy.defs.load_definitions()[name]


def _pair(name, key=_KEY):
    """An ``(Encoder, Decoder)`` pair in format mode for one variable format."""
    return realism.record_layer_pair(_spec(name), hybrid=False, key=key)


def _variable(name, key=_KEY):
    return fteproxy._variable_lengths_for_spec(_spec(name), key)


def _frame(name, wire):
    """Split a format-mode wire the way *this* format's decoder frames it.

    On the terminator, or on the length prefix. Tests that are about a property
    every variable-length format has -- the spread, one record per payload that
    fits -- go through here rather than assuming a terminator, so they cover
    both framings without being written twice.
    """
    return realism.frame_wire(wire, _spec(name))


# --------------------------------------------------------------------------- #
# The length set
# --------------------------------------------------------------------------- #

class TestAllowedLengths:

    @pytest.mark.parametrize('name', sorted(VARIABLE))
    def test_the_set_spans_the_declared_range(self, name):
        spec = _spec(name)
        lengths = fteproxy.defs.spec_allowed_lengths(spec)
        assert lengths == tuple(sorted(set(lengths)))
        assert len(lengths) == fteproxy.defs.LENGTH_STEPS
        assert lengths[0] == spec['min_length']
        assert lengths[-1] == spec['max_length']

    @pytest.mark.parametrize('name', sorted(VARIABLE))
    def test_every_length_carries_at_least_one_data_record(self, name):
        """The floor for the *shortest* length: a type byte, the seal, and a
        byte of payload. The 128-byte capacity floor applies at max_length,
        where the handshake lives."""
        variable = _variable(name)
        assert min(variable.capacities.values()) >= 1
        assert variable.capacities[variable.max_length] >= \
            fteproxy.defs.MIN_CAPACITY - rl._SEAL_OVERHEAD - rl._TYPE_LEN

    @pytest.mark.parametrize('name', sorted(VARIABLE))
    def test_both_ends_derive_the_same_set(self, name):
        """Nothing about the length set is negotiated: it is a function of the
        definitions entry, so a sender's choice is a receiver's expectation."""
        spec = _spec(name)
        assert (fteproxy.defs.get_allowed_lengths(name)
                == fteproxy.defs.spec_allowed_lengths(spec))
        assert fteproxy.defs.get_terminator(name) == VARIABLE[name]
        assert fteproxy.defs.is_variable(name)
        # The framing is a function of the entry too, so neither end has to be
        # told which delimiter the other is writing.
        expected = (fteproxy.defs.FRAMING_LENGTH_PREFIX if name in PREFIXED
                    else fteproxy.defs.FRAMING_TERMINATOR)
        assert fteproxy.defs.get_framing(name) == expected
        assert _variable(name).framing == expected

    @pytest.mark.parametrize('name', sorted(VARIABLE))
    def test_get_length_is_the_top_of_the_range(self, name):
        """What the fixed-frame paths use: the handshake, the server's
        first-record scan, and a hybrid header."""
        assert fteproxy.defs.getLength(name) == _spec(name)['max_length']

    def test_a_partial_declaration_is_refused_at_load(self):
        """A range with no terminator would silently load as fixed length and
        emit one length again, so it fails at load instead."""
        for broken in ({'regex': r'^[a-z]+\r\n$', 'min_length': 64,
                        'max_length': 256},
                       {'regex': r'^[a-z]+\r\n$', 'terminator': '\r\n'},
                       {'regex': r'^[a-z]+\r\n$', 'min_length': 64,
                        'max_length': 256, 'terminator': '\r\n',
                        'length': 128}):
            with pytest.raises(fteproxy.defs.DefinitionsError):
                fteproxy.defs.check_capacities({'broken-request': broken})

    def test_an_inverted_range_is_refused(self):
        with pytest.raises(fteproxy.defs.DefinitionsError):
            fteproxy.defs.check_capacities({'broken-request': {
                'regex': r'^[a-z]+\r\n$', 'min_length': 256,
                'max_length': 64, 'terminator': '\r\n'}})


# --------------------------------------------------------------------------- #
# Framing
# --------------------------------------------------------------------------- #

class TestFraming:

    @pytest.mark.parametrize('name', sorted(VARIABLE))
    def test_records_of_many_sizes_round_trip(self, name):
        encoder, decoder = _pair(name)
        for i in range(24):
            payload = os.urandom((i * 29) % (encoder.capacity + 1))
            encoder.push(payload)
            decoder.push(encoder.pop())
            assert decoder.pop() == payload
        assert not decoder.failed

    @pytest.mark.parametrize('name', sorted(TERMINATED))
    def test_every_covertext_ends_with_the_terminator_and_nothing_else_does(
            self, name):
        terminator = VARIABLE[name]
        encoder, _decoder = _pair(name)
        encoder.push(os.urandom(20000))
        wire = encoder.pop()
        covertexts = validate.frame_covertexts(wire, terminator)
        assert len(covertexts) > 1
        for covertext in covertexts:
            assert covertext.endswith(terminator)
            assert terminator not in covertext[:-len(terminator)]
        assert b''.join(covertexts) == wire

    @pytest.mark.parametrize('name', ['ftp-request', 'http-request',
                                      'dns-request', 'dns-response'])
    def test_a_record_split_at_every_byte_reassembles(self, name):
        """Including every split *inside* the delimiter, which is the case a
        fixed-length decoder never had to think about: a partial terminator, or
        one byte of a two-byte length prefix, must read as "not yet", never as
        a short record."""
        encoder, _ = _pair(name)
        payload = b'the quick brown fox'
        encoder.push(payload)
        wire = encoder.pop()
        assert len(_frame(name, wire)) == 1

        for split in range(1, len(wire)):
            _encoder, decoder = _pair(name)
            decoder.push(wire[:split])
            assert decoder.pop() == b'', 'emitted early at split %d' % split
            assert not decoder.failed, 'failed at split %d' % split
            decoder.push(wire[split:])
            assert decoder.pop() == payload, 'lost at split %d' % split

    @pytest.mark.parametrize('name', sorted(VARIABLE))
    def test_a_multi_record_wire_delivered_in_odd_chunks(self, name):
        encoder, decoder = _pair(name)
        payload = bytes(range(256)) * 40
        encoder.push(payload)
        wire = encoder.pop()
        out = b''
        for offset in range(0, len(wire), 37):
            decoder.push(wire[offset:offset + 37])
            out += decoder.pop()
        assert out == payload

    def test_control_records_interleave_with_data(self):
        encoder, decoder = _pair('http-request')
        wire = encoder.encode(rl.OPEN, b'dest')
        encoder.push(b'payload')
        wire += encoder.pop()
        wire += encoder.encode(rl.CLOSE)
        decoder.push(wire)
        assert decoder.pop_records() == [
            (rl.OPEN, b'dest'),
            (rl.DATA, b'payload'),
            (rl.CLOSE, b''),
        ]

    def test_a_reordered_record_is_rejected(self):
        """The seal still stamps the stream position, so the same record in the
        wrong place does not decode -- variable length changes framing, not the
        anti-replay guarantee."""
        encoder, _ = _pair('ftp-request')
        encoder.push(b'first')
        first = encoder.pop()
        encoder.push(b'second')
        second = encoder.pop()

        _e, ordered = _pair('ftp-request')
        ordered.push(first + second)
        assert ordered.pop() == b'firstsecond'

        _e, swapped = _pair('ftp-request')
        swapped.push(second + first)
        assert swapped.pop() == b''
        assert swapped.failed


# --------------------------------------------------------------------------- #
# Fail-closed
# --------------------------------------------------------------------------- #

class TestFailsClosed:

    def test_a_length_the_format_does_not_emit_is_refused(self):
        """A covertext that is in the format's language, sealed with the right
        key, at a length between two allowed ones. Only the length is wrong, and
        that alone kills the stream: framing cannot be salvaged by hunting for a
        later terminator."""
        spec = _spec('http-request')
        lengths = fteproxy.defs.spec_allowed_lengths(spec)
        odd = (lengths[0] + lengths[1]) // 2
        assert odd not in lengths
        odd_cipher = fteproxy._make_cipher(spec['regex'], odd, _KEY)
        record = rl._seal(odd_cipher, bytes((rl.DATA,)) + b'hello', 0)
        assert len(record) == odd
        assert record.endswith(b'\r\n\r\n')

        _encoder, decoder = _pair('http-request')
        decoder.push(record)
        assert decoder.pop_records() == []
        assert decoder.failed
        assert decoder._buffer == b''
        with pytest.raises(rl.StreamFailedError):
            decoder.push(b'more')

    def test_a_corrupted_covertext_is_refused(self):
        """One flipped bit in a field, so the length and the terminator are
        untouched and only the seal notices."""
        encoder, decoder = _pair('sip-request')
        encoder.push(b'payload')
        wire = bytearray(encoder.pop())
        index = next(i for i, byte in enumerate(wire)
                     if i > 40 and byte >= 0x20)      # inside a field, printable
        wire[index] ^= 0x01
        decoder.push(bytes(wire))
        assert decoder.pop_records() == []
        assert decoder.failed

    def test_good_records_before_a_bad_one_are_delivered(self):
        encoder, decoder = _pair('ftp-response')
        encoder.push(b'first')
        good = encoder.pop()
        decoder.push(good + b'X' * 8 + b'\r\n')
        assert decoder.pop() == b'first'
        assert decoder.failed

    @pytest.mark.parametrize('name', sorted(TERMINATED))
    def test_a_peer_that_never_terminates_cannot_grow_the_buffer(self, name):
        """Terminator framing has no natural bound of its own, so one is
        imposed: more than one longest covertext with no terminator in it is
        not a record that is still arriving, it is a peer feeding the buffer."""
        _encoder, decoder = _pair(name)
        maximum = _spec(name)['max_length']

        decoder.push(b'A' * maximum)            # could still become a record
        assert decoder.pop_records() == []
        assert not decoder.failed
        assert len(decoder._buffer) == maximum

        decoder.push(b'A')                      # now it cannot
        assert decoder.pop_records() == []
        assert decoder.failed
        assert decoder._buffer == b''
        with pytest.raises(rl.StreamFailedError):
            decoder.push(b'A' * 64)

    def test_the_decoder_bounds_itself_by_the_longest_covertext(self):
        for name in sorted(VARIABLE):
            _encoder, decoder = _pair(name)
            assert decoder.max_record_bytes == _spec(name)['max_length']


# --------------------------------------------------------------------------- #
# The spread: the fingerprint this phase exists to remove
# --------------------------------------------------------------------------- #

class TestLengthSpread:

    @pytest.mark.parametrize('name', sorted(VARIABLE))
    def test_a_mixed_stream_produces_many_lengths_and_no_dominant_one(self, name):
        """Interactive-sized writes and bulk writes together, as a relayed
        session carries. Before F7 this histogram had exactly one bar."""
        encoder, _decoder = _pair(name)
        wire = b''
        for i in range(120):
            encoder.push(os.urandom(1 + (i * 13) % 40))      # small messages
            wire += encoder.pop()
        for _ in range(12):
            encoder.push(os.urandom(4096))                   # bulk
            wire += encoder.pop()

        covertexts = _frame(name, wire)
        histogram = collections.Counter(len(c) for c in covertexts)
        allowed = set(fteproxy.defs.spec_allowed_lengths(_spec(name)))
        assert set(histogram) <= allowed
        assert len(histogram) >= 6, histogram
        assert max(histogram.values()) <= 0.5 * len(covertexts), histogram

    def test_small_writes_lean_short_and_bulk_leans_long(self):
        """The bias is what makes the spread look like traffic rather than like
        a random number generator: a chat session should not emit 700-byte
        requests every time, and a download should not emit 200-byte ones."""
        name = 'http-request'
        terminator = VARIABLE[name]
        lengths = fteproxy.defs.spec_allowed_lengths(_spec(name))
        midpoint = lengths[len(lengths) // 2]

        def mean_length(chunks):
            encoder, _ = _pair(name)
            wire = b''
            for chunk in chunks:
                encoder.push(chunk)
                wire += encoder.pop()
            sizes = [len(c) for c in
                     validate.frame_covertexts(wire, terminator)]
            return sum(sizes) / len(sizes)

        interactive = mean_length([os.urandom(8) for _ in range(200)])
        bulk = mean_length([os.urandom(20000) for _ in range(4)])
        assert interactive < midpoint < bulk

    def test_a_record_is_never_split_to_look_shorter(self):
        """A payload that fits in one record travels as one record: the length
        choice never picks a length too small to hold what is queued."""
        for name in sorted(VARIABLE):
            encoder, _ = _pair(name)
            payload = os.urandom(encoder.capacity)
            encoder.push(payload)
            wire = encoder.pop()
            assert len(_frame(name, wire)) == 1
            assert len(wire) == max(
                fteproxy.defs.spec_allowed_lengths(_spec(name)))


# --------------------------------------------------------------------------- #
# Terminator uniqueness
# --------------------------------------------------------------------------- #

#: What ``http-response`` looked like before F7: the trailing field absorbed a
#: body and admitted CR and LF, so a covertext could carry ``\r\n\r\n`` inside
#: it and terminator framing would cut the record in half.
_PRE_F7_HTTP_RESPONSE = (
    '^HTTP/1\\.1 (200 OK|302 Found|404 Not Found)\r\n'
    'Content-Type: [a-zA-Z0-9/;=. +-]+\r\n'
    'Content-Length: [0-9]+\r\n'
    'Server: [a-zA-Z0-9/. ()_-]+\r\n'
    '\r\n[a-zA-Z0-9/+= \r\n-]*$')


class TestTerminatorUniqueness:

    @pytest.mark.parametrize('name', sorted(TERMINATED))
    def test_every_shipped_variable_format_passes_the_static_check(self, name):
        validate.check_terminator_uniqueness(
            name, _spec(name)['regex'], VARIABLE[name])

    @pytest.mark.parametrize('name', sorted(TERMINATED))
    def test_sampled_covertexts_agree_with_the_static_check(self, name):
        covertexts = realism.format_covertexts(_spec(name), n=64)
        validate._check_sampled_terminators(name, covertexts, VARIABLE[name])

    def test_the_pre_f7_http_response_body_field_is_rejected(self):
        """The regression this check exists for: a body-absorbing field. It
        fails on the first condition -- a pattern whose last atom is a field
        rather than the terminator cannot have the terminator as its suffix at
        all, which is why F7 ended the response at the header block."""
        with pytest.raises(validate.FormatValidationError) as excinfo:
            validate.check_terminator_uniqueness(
                'http-response', _PRE_F7_HTTP_RESPONSE, b'\r\n\r\n')
        assert 'does not end with its terminator' in str(excinfo.value)

    def test_a_class_that_admits_a_terminator_byte_is_rejected(self):
        """Even ending in the terminator is not enough: a field that can carry
        a CR or an LF could reproduce it mid-covertext."""
        with pytest.raises(validate.FormatValidationError) as excinfo:
            validate.check_terminator_uniqueness(
                'x-response', '^Body: [a-z\r\n]+\r\n\r\n$', b'\r\n\r\n')
        assert 'character class' in str(excinfo.value)

    def test_a_literal_that_repeats_the_terminator_is_rejected(self):
        """No class carries a terminator byte here; the literals do, twice."""
        with pytest.raises(validate.FormatValidationError) as excinfo:
            validate.check_terminator_uniqueness(
                'x-request', '^A: [a-z]+\r\n\r\nB: [a-z]+\r\n\r\n$',
                b'\r\n\r\n')
        assert 'literal text' in str(excinfo.value)

    @pytest.mark.parametrize('regex,terminator,why', [
        ('^(X\r|Y)\nZ: [a-z]+\r\n$', b'\r\n',
         'a branch ends in CR and what follows the group starts with LF'),
        ('^A\rB?\nC: [a-z]+\r\n$', b'\r\n',
         'an optional literal, absent, puts CR next to LF'),
        ('^X(\r\n)+Y: [a-z]+\r\n\r\n$', b'\r\n\r\n',
         'a repeated unit meets itself'),
    ])
    def test_adjacencies_a_single_concatenation_would_miss(self, regex,
                                                           terminator, why):
        """The literal check expands alternation branches and optional atoms
        rather than concatenating the pattern's literals once. Each of these
        can produce the terminator mid-covertext, and a single concatenated
        skeleton shows none of them."""
        with pytest.raises(validate.FormatValidationError) as excinfo:
            validate.check_terminator_uniqueness('x-request', regex, terminator)
        assert 'literal text' in str(excinfo.value), why

    def test_a_pattern_too_complex_to_prove_is_refused_not_passed(self):
        """Failing open here would mean shipping a format whose framing is not
        proven, so the expansion cap is a validation failure."""
        explosive = '^' + '(a|b|c|d)' * 20 + 'X\r\n$'
        with pytest.raises(validate.FormatValidationError) as excinfo:
            validate.check_terminator_uniqueness('x-request', explosive, b'\r\n')
        assert 'too many' in str(excinfo.value)

    def test_a_pattern_that_does_not_end_with_its_terminator_is_rejected(self):
        with pytest.raises(validate.FormatValidationError):
            validate.check_terminator_uniqueness(
                'x-request', '^GET /[a-z]+ HTTP/1\\.1$', b'\r\n')

    def test_a_negated_class_is_rejected(self):
        with pytest.raises(validate.FormatValidationError):
            validate.check_terminator_uniqueness(
                'x-request', '^[^!]+\r\n$', b'\r\n')

    def test_validate_format_refuses_a_format_whose_terminator_is_not_unique(self):
        spec = {'regex': _PRE_F7_HTTP_RESPONSE, 'min_length': 200,
                'max_length': 700, 'terminator': '\r\n\r\n',
                'mode_hint': 'format'}
        with pytest.raises(validate.FormatValidationError):
            validate.validate_format('http-response', spec, samples=2)

    def test_the_class_scanner_reads_the_dialect(self):
        """Ranges expand, a leading or trailing ``-`` is itself, and there are
        no backslash escapes inside a class."""
        assert validate._class_members('a-c') == set('abc')
        assert validate._class_members('a-z.-') == set('abcdefghijklmnopqrstuvwxyz.-')
        assert validate._class_members('-ab') == set('-ab')
        assert validate._class_members('^a') is None

    def test_skeletons_expand_branches_and_optional_atoms(self):
        any_ = validate._ANY
        assert validate._literal_skeletons('(GET|PUT) /') == {'GET /', 'PUT /'}
        assert validate._literal_skeletons('/[a-z]*x') == {'/x', '/' + any_ + 'x'}
        assert validate._literal_skeletons('[a-z]+') == {any_}
        assert validate._literal_skeletons('a?b') == {'b', 'ab'}


# --------------------------------------------------------------------------- #
# Length-prefix framing (F7b): the delimiter dns uses
# --------------------------------------------------------------------------- #

class TestLengthPrefixFraming:
    """What terminator framing's tests above prove for the text formats, proved
    for the delimiter ``dns`` uses instead.

    A record is a two-byte big-endian message length followed by that many
    bytes. The prefix is framing rather than language, so there is nothing here
    to prove *about the pattern* -- the questions are all about the wire: does
    the prefix say what follows it, does the decoder wait for a partial record
    and refuse an impossible one, and is what comes out still DNS.
    """

    PREFIX = fteproxy.defs.LENGTH_PREFIX_BYTES

    @pytest.mark.parametrize('name', PREFIXED)
    def test_the_prefix_announces_the_message_and_the_regex_is_the_message(
            self, name):
        """The two halves of "the prefix is framing, not language": on the wire
        each record's prefix accounts for exactly the bytes after it, and what
        those bytes match is the format's regex -- which no longer describes the
        prefix at all."""
        spec = _spec(name)
        pattern = re.compile(spec['regex'].encode('latin-1'), re.DOTALL)
        allowed = set(fteproxy.defs.spec_allowed_lengths(spec))

        encoder, _decoder = _pair(name)
        wire = b''
        for i in range(80):
            encoder.push(os.urandom(1 + (i * 11) % 60))
            wire += encoder.pop()

        covertexts = _frame(name, wire)
        assert len(covertexts) > 1
        assert b''.join(covertexts) == wire
        for covertext in covertexts:
            assert len(covertext) in allowed
            declared = int.from_bytes(covertext[:self.PREFIX], 'big')
            assert declared == len(covertext) - self.PREFIX
            assert pattern.fullmatch(covertext[self.PREFIX:])
            # ... and the prefix itself is not in the language: the regex
            # matches the message and only the message.
            assert not pattern.fullmatch(covertext)

    @pytest.mark.parametrize('name', PREFIXED)
    def test_two_records_split_at_every_byte_reassemble(self, name):
        """Every split across the whole two-record wire: inside the first
        prefix, inside the first message, exactly on the record boundary,
        inside the second prefix, and inside the second message. One byte of a
        two-byte prefix must read as "not yet", never as a length."""
        encoder, _ = _pair(name)
        encoder.push(b'first')
        wire = encoder.pop()
        encoder.push(b'second and rather longer')
        wire += encoder.pop()
        assert len(_frame(name, wire)) == 2

        for split in range(1, len(wire)):
            _encoder, decoder = _pair(name)
            decoder.push(wire[:split])
            head = decoder.pop()
            assert not decoder.failed, 'failed at split %d' % split
            decoder.push(wire[split:])
            assert head + decoder.pop() == b'firstsecond and rather longer', \
                'lost at split %d' % split
            assert not decoder.failed, 'failed at split %d' % split

    @pytest.mark.parametrize('name', PREFIXED)
    def test_a_prefix_not_in_the_allowed_set_fails_closed(self, name):
        """A covertext in the format's language, sealed with the right key, at
        a message length between two allowed ones, behind a prefix that
        honestly describes it. Only the length is wrong, and that alone kills
        the stream -- exactly as a terminator-framed record of an unlisted
        length does."""
        spec = _spec(name)
        lengths = fteproxy.defs.spec_allowed_lengths(spec)
        odd = (lengths[0] + lengths[1]) // 2
        assert odd not in lengths
        odd_cipher = fteproxy._spec_cipher(spec, odd, _KEY)
        record = rl._seal(odd_cipher, bytes((rl.DATA,)) + b'hello', 0)
        assert len(record) == odd
        assert int.from_bytes(record[:self.PREFIX], 'big') == odd - self.PREFIX

        _encoder, decoder = _pair(name)
        decoder.push(record)
        assert decoder.pop_records() == []
        assert decoder.failed
        assert decoder._buffer == b''
        with pytest.raises(rl.StreamFailedError):
            decoder.push(b'more')

    @pytest.mark.parametrize('name', PREFIXED)
    def test_an_impossible_prefix_fails_closed_at_once_and_buffers_nothing(
            self, name):
        """The bound this framing gets for free. A 65535-byte prefix is a
        protocol violation, not a large record still arriving, so it is refused
        the moment it is read rather than waited on -- which is what stops a
        peer talking the decoder into holding 64 KiB on its say-so."""
        _encoder, decoder = _pair(name)
        decoder.push(b'\xff\xff' + b'A' * 8)
        assert decoder.pop_records() == []
        assert decoder.failed
        assert decoder._buffer == b''
        with pytest.raises(rl.StreamFailedError):
            decoder.push(b'A' * 64)

    @pytest.mark.parametrize('name', PREFIXED)
    def test_a_truncated_message_waits_and_then_fails_on_what_follows(self, name):
        """A record short of the length its prefix announced is not a short
        record: while the bytes could still be arriving the decoder waits, and
        once the announced count is filled by bytes that are not that covertext
        the seal notices and the stream dies."""
        encoder, _ = _pair(name)
        encoder.push(b'first record')
        first = encoder.pop()
        encoder.push(b'second record')
        second = encoder.pop()

        # Still arriving: no record, no failure, everything still buffered.
        _e, waiting = _pair(name)
        waiting.push(first[:-1])
        assert waiting.pop_records() == []
        assert not waiting.failed
        assert len(waiting._buffer) == len(first) - 1

        # A byte of the first record dropped: the prefix still says W, so the
        # frame fills up with the head of the next record and does not decrypt.
        _e, truncated = _pair(name)
        truncated.push(first[:-1] + second)
        assert truncated.pop_records() == []
        assert truncated.failed
        assert truncated._buffer == b''

    @pytest.mark.parametrize('name', PREFIXED)
    def test_the_spread_is_a_spread_and_every_covertext_is_still_dns(self, name):
        """The point of F7b, and its constraint. A mixed stream produces a
        histogram of wire lengths rather than one bar -- and every covertext in
        it is still judged a structurally valid DNS-over-TCP message by the
        independent parser in ``realism.dns``, which knows only RFC 1035 and
        never sees the format's regex."""
        spec = _spec(name)
        encoder, _decoder = _pair(name)
        wire = b''
        for i in range(150):
            encoder.push(os.urandom(1 + (i * 7) % 30))       # small messages
            wire += encoder.pop()
        for _ in range(10):
            encoder.push(os.urandom(4096))                   # bulk
            wire += encoder.pop()

        covertexts = _frame(name, wire)
        histogram = collections.Counter(len(c) for c in covertexts)
        assert set(histogram) <= set(fteproxy.defs.spec_allowed_lengths(spec))
        assert len(histogram) >= 6, histogram
        assert max(histogram.values()) <= 0.5 * len(covertexts), histogram

        for covertext in covertexts:
            dns_realism.check(covertext)
        realism.statistical_guard(covertexts)

    @pytest.mark.parametrize('name', PREFIXED)
    def test_the_question_name_is_what_the_length_buys(self, name):
        """Why the spread is worth having here: the covertext length lands in
        QNAME, so a histogram of lengths is a histogram of query-name sizes,
        and the shortest is a name a resolver could plausibly be asked for
        rather than the 254-octet pad a fixed length forced."""
        encoder, _decoder = _pair(name)
        wire = b''
        for _ in range(200):
            encoder.push(b'x')
            wire += encoder.pop()

        names = {dns_realism.parse(c).name_octets for c in _frame(name, wire)}
        assert len(names) >= 6, names
        assert min(names) < 80
        assert max(names) <= 255


# --------------------------------------------------------------------------- #
# What did not change
# --------------------------------------------------------------------------- #

class _Recorder:
    """A socket that remembers every ``sendall``, and is otherwise the real one."""

    def __init__(self, sock):
        self._sock = sock
        self.sent = []

    def sendall(self, data):
        self.sent.append(bytes(data))
        return self._sock.sendall(data)

    def __getattr__(self, name):
        return getattr(self._sock, name)


class _Reader(threading.Thread):
    """Drains a wrapper in the background while the other end writes.

    A ``socketpair``'s kernel buffer is a few kilobytes, so a sender that writes
    more than that with nobody reading blocks forever. One reader and one
    writer on a wrapper is exactly how the relay uses it.
    """

    def __init__(self, wrapper, expected):
        super().__init__(daemon=True)
        self._wrapper = wrapper
        self._expected = expected
        self.data = b''

    def run(self):
        while len(self.data) < self._expected:
            chunk = self._wrapper.recv(65536)
            if not chunk:
                break
            self.data += chunk


class TestFixedFramingSurvives:

    def _handshaken(self, base, mode):
        """A real client/server pair over a socketpair, handshake completed."""
        client_sock, server_sock = socket.socketpair()
        client = fteproxy.wrap_socket(client_sock, server_id=SERVER_PUBLIC,
                                      format=base, mode=mode)
        client._socket = _Recorder(client_sock)
        server = fteproxy.wrap_socket(server_sock, server_key=SERVER_PRIVATE)
        errors = []

        def accept():
            try:
                server.handshake()
            except Exception as e:                      # pragma: no cover
                errors.append(e)

        thread = threading.Thread(target=accept)
        thread.start()
        try:
            client.handshake()
        finally:
            thread.join(10)
        assert not errors, errors
        return client, server

    @pytest.mark.parametrize('mode', ['format', 'hybrid'])
    def test_the_client_hello_is_one_max_length_covertext(self, mode):
        """The handshake is fixed length in both modes: the server's
        first-record scan reads exactly ``max_length`` bytes and tries to unseal
        them, so a hello at any other length would never be found."""
        client, server = self._handshaken('http', mode)
        try:
            hello = client._socket.sent[0]
            assert len(hello) == fteproxy.defs.getLength('http-request')
            assert len(hello) == _spec('http-request')['max_length']
            assert server.handshake_complete
            assert server.negotiated_mode == mode
        finally:
            client.close()
            server.close()

    def test_format_mode_carries_traffic_and_varies_its_lengths(self):
        """End to end through the socket wrapper: the session encoder is the
        variable one, and what goes on the wire after the hello is a spread of
        lengths that all decode."""
        client, server = self._handshaken('http', 'format')
        try:
            assert client._encoder._variable is not None
            assert client._decoder._variable is not None
            expected = b''.join(b'x' * (1 + i * 7) for i in range(60))
            reader = _Reader(server, len(expected))
            reader.start()
            for i in range(60):
                client.send(b'x' * (1 + i * 7))
            reader.join(20)
            assert reader.data == expected

            data_records = b''.join(client._socket.sent[1:])
            lengths = {len(c) for c in
                       validate.frame_covertexts(data_records, b'\r\n\r\n')}
            assert len(lengths) >= 3, lengths
            assert lengths <= set(
                fteproxy.defs.spec_allowed_lengths(_spec('http-request')))
        finally:
            client.close()
            server.close()

    def test_a_hybrid_header_is_still_fixed_at_max_length(self):
        client, server = self._handshaken('http', 'hybrid')
        try:
            assert client._encoder._variable is None
            assert client._decoder._variable is None
            reader = _Reader(server, 4000)
            reader.start()
            client.send(b'z' * 4000)
            reader.join(20)
            assert reader.data == b'z' * 4000
            header = client._socket.sent[1]
            length = fteproxy.defs.getLength('http-request')
            pattern = re.compile(
                _spec('http-request')['regex'].encode('latin-1'), re.DOTALL)
            assert pattern.fullmatch(header[:length])
            assert len(header) > length          # header plus a raw body
        finally:
            client.close()
            server.close()

    def test_the_dns_hello_is_one_max_length_covertext(self):
        """F7b changed what a dns *data* record looks like and nothing about the
        handshake. The hello is still one fixed frame at ``max_length``, still
        272 bytes, and -- because the record layer writes the framing prefix in
        front of the sealed message -- still a structurally valid DNS query,
        which is what it was before the prefix left the regex."""
        client, server = self._handshaken('dns', 'format')
        try:
            hello = client._socket.sent[0]
            assert len(hello) == fteproxy.defs.getLength('dns-request')
            assert len(hello) == _spec('dns-request')['max_length'] == 272
            dns_realism.check(hello)
            assert server.handshake_complete
        finally:
            client.close()
            server.close()

    def test_the_four_text_formats_kept_their_terminator_framing(self):
        """F7b touched the dns fragment and nothing else. The four formats F7
        gave a terminator declare exactly what they declared then -- no
        ``framing`` key, a terminator, and the same range."""
        expected = {
            'http-request': (200, 700), 'http-response': (200, 700),
            'ftp-request': (64, 256), 'ftp-response': (64, 256),
            'smtp-request': (80, 320), 'smtp-response': (80, 320),
            'sip-request': (300, 800), 'sip-response': (300, 800),
        }
        for name, (low, high) in expected.items():
            spec = _spec(name)
            assert 'framing' not in spec, name
            assert (spec['min_length'], spec['max_length']) == (low, high), name
            assert fteproxy.defs.spec_framing(spec) == \
                fteproxy.defs.FRAMING_TERMINATOR, name
            assert fteproxy.defs.spec_terminator(spec) == TERMINATED[name], name

    def test_the_shape_catalog_is_still_fixed_length(self):
        fteproxy.conf.setValue('fteproxy.defs.release', '20260110')
        fteproxy.defs._definitions = None
        definitions = fteproxy.defs.load_definitions()
        for name, spec in definitions.items():
            assert not fteproxy.defs.spec_is_variable(spec), name
            assert len(fteproxy.defs.spec_allowed_lengths(spec)) == 1, name
        assert fteproxy._variable_for('manual-http-request', _KEY) is None

    def test_hybrid_refuses_to_carry_a_variable_length_format(self):
        """The two framings are exclusive; wiring both would be a bug that only
        showed up as a stream that will not decode."""
        variable = _variable('http-request')
        cipher = fteproxy._make_cipher(
            _spec('http-request')['regex'], 700, _KEY)
        body = fteproxy._make_body_cipher(_KEY)
        with pytest.raises(ValueError):
            rl.Encoder(cipher=cipher, body_cipher=body, variable=variable)
        with pytest.raises(ValueError):
            rl.Decoder(cipher=cipher, body_cipher=body, variable=variable)
