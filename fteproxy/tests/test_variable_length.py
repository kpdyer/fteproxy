#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Variable-length covertexts (phase F7).

Until now every covertext of a format was exactly one length, which SECURITY.md
called out as its own fingerprint: a length-distribution test separates a tunnel
from real traffic without looking at a single byte. The four text formats
(``http``, ``ftp``, ``smtp``, ``sip``) now pick a covertext length per
format-mode record from a small set spanning ``[min_length, max_length]``, and
the decoder frames the wire on the format's terminator instead of on a fixed
slice.

What these tests pin down:

* the **length set** both ends derive from the definitions, without negotiating it;
* **framing**: a record delivered in fragments, including a split inside the
  terminator itself, reassembles; a length the format does not emit, a corrupted
  covertext, and a peer that never sends a terminator each fail the stream
  closed rather than being buffered or guessed at;
* the **spread**: a stream of small and large writes produces many distinct
  covertext lengths and no dominant one, which is the point of the change;
* **terminator uniqueness**, the property framing rests on, including that the
  pre-F7 ``http-response`` regex (which absorbed a body and so could carry a
  CRLF CRLF inside a covertext) is rejected by the check;
* what did **not** change: the two handshake records and a ``hybrid`` header are
  still one fixed ``max_length`` covertext, and ``dns`` and the shape catalog
  are still framed by their fixed length.
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


_KEY = bytes(range(32))

#: The variable-length formats the 20260903 release ships, with the terminator
#: each one is framed on.
VARIABLE = {
    'http-request': b'\r\n\r\n',
    'http-response': b'\r\n\r\n',
    'ftp-request': b'\r\n',
    'ftp-response': b'\r\n',
    'smtp-request': b'\r\n',
    'smtp-response': b'\r\n',
    'sip-request': b'\r\n\r\n',
    'sip-response': b'\r\n\r\n',
}

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

class TestTerminatorFraming:

    @pytest.mark.parametrize('name', sorted(VARIABLE))
    def test_records_of_many_sizes_round_trip(self, name):
        encoder, decoder = _pair(name)
        for i in range(24):
            payload = os.urandom((i * 29) % (encoder.capacity + 1))
            encoder.push(payload)
            decoder.push(encoder.pop())
            assert decoder.pop() == payload
        assert not decoder.failed

    @pytest.mark.parametrize('name', sorted(VARIABLE))
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

    @pytest.mark.parametrize('name', ['ftp-request', 'http-request'])
    def test_a_record_split_at_every_byte_reassembles(self, name):
        """Including every split *inside* the terminator, which is the case a
        fixed-length decoder never had to think about: a partial terminator
        must read as "not yet", never as a short record."""
        encoder, _ = _pair(name)
        payload = b'the quick brown fox'
        encoder.push(payload)
        wire = encoder.pop()
        assert len(validate.frame_covertexts(wire, VARIABLE[name])) == 1

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

    @pytest.mark.parametrize('name', sorted(VARIABLE))
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
        terminator = VARIABLE[name]
        encoder, _decoder = _pair(name)
        wire = b''
        for i in range(120):
            encoder.push(os.urandom(1 + (i * 13) % 40))      # small messages
            wire += encoder.pop()
        for _ in range(12):
            encoder.push(os.urandom(4096))                   # bulk
            wire += encoder.pop()

        covertexts = validate.frame_covertexts(wire, terminator)
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
            terminator = VARIABLE[name]
            encoder, _ = _pair(name)
            payload = os.urandom(encoder.capacity)
            encoder.push(payload)
            wire = encoder.pop()
            assert len(validate.frame_covertexts(wire, terminator)) == 1
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

    @pytest.mark.parametrize('name', sorted(VARIABLE))
    def test_every_shipped_variable_format_passes_the_static_check(self, name):
        validate.check_terminator_uniqueness(
            name, _spec(name)['regex'], VARIABLE[name])

    @pytest.mark.parametrize('name', sorted(VARIABLE))
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

    def test_dns_is_still_fixed_length(self):
        """Its 2-byte length prefix is a literal in the regex, so a second
        covertext length would need a second regex. It stays at 272."""
        for name in ('dns-request', 'dns-response'):
            spec = _spec(name)
            assert not fteproxy.defs.spec_is_variable(spec)
            assert fteproxy.defs.spec_allowed_lengths(spec) == (272,)
            assert fteproxy.defs.getLength(name) == 272
            assert fteproxy._variable_for(name, _KEY) is None

        encoder, decoder = realism.record_layer_pair(_spec('dns-request'),
                                                     key=_KEY)
        assert encoder._variable is None
        encoder.push(os.urandom(1000))
        wire = encoder.pop()
        assert len(wire) % 272 == 0
        decoder.push(wire)
        assert len(decoder.pop()) == 1000

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
