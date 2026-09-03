#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the protocol v1 handshake: vectors, tampering, replay, epoch.

The vectors in ``vectors/handshake_v1.json`` pin the wire format and the key
schedule. They were generated once from fixed seeds; if a change to
:mod:`fteproxy.handshake` breaks them, that change breaks interoperation with
every deployed 0.4 peer, and the version must move rather than the vectors.
"""

import json
import os

import pytest

import fteproxy
import fteproxy.handshake as hs


VECTORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'vectors', 'handshake_v1.json')


def load_vectors():
    with open(VECTORS_PATH) as fh:
        return json.load(fh)


VECTORS = load_vectors()
CASES = VECTORS['cases']
CASE_IDS = [case['name'] for case in CASES]


def unhex(value):
    return bytes.fromhex(value)


def client_for(case):
    return hs.ClientHandshake(
        server_public=unhex(case['server_public']), format=case['format'],
        mode=case['mode'], defs=case['defs'], epoch=case['epoch'],
        ephemeral_private=unhex(case['client_ephemeral_private']))


def accept(case, hello_bytes, **overrides):
    kwargs = dict(
        server_private=unhex(case['server_private']),
        server_public=unhex(case['server_public']),
        defs=case['defs'], formats={case['format']}, replay=None,
        now_epoch=case['epoch'],
        ephemeral_private=unhex(case['server_ephemeral_private']))
    kwargs.update(overrides)
    return hs.accept_client_hello(hello_bytes, **kwargs)


class TestVectors:
    """Every derived value matches the checked-in vector, byte for byte."""

    def test_version(self):
        assert VECTORS['protocol_version'] == hs.PROTOCOL_VERSION

    @pytest.mark.parametrize('case', CASES, ids=CASE_IDS)
    def test_server_id_matches(self, case):
        assert hs.server_id(unhex(case['server_private'])) == \
            unhex(case['server_public'])

    @pytest.mark.parametrize('case', CASES, ids=CASE_IDS)
    def test_cover_key_matches(self, case):
        assert hs.cover_key(unhex(case['server_public'])) == \
            unhex(case['cover_key'])

    @pytest.mark.parametrize('case', CASES, ids=CASE_IDS)
    def test_client_hello_bytes_match(self, case):
        assert client_for(case).hello_bytes == unhex(case['client_hello'])

    @pytest.mark.parametrize('case', CASES, ids=CASE_IDS)
    def test_client_hello_decodes_to_its_fields(self, case):
        hello = hs.ClientHello.decode(unhex(case['client_hello']))
        assert hello.version == hs.PROTOCOL_VERSION
        assert hello.mode == case['mode']
        assert hello.defs == case['defs']
        assert hello.format == case['format']
        assert hello.epoch == case['epoch']
        assert hello.client_public == unhex(case['client_ephemeral_public'])

    @pytest.mark.parametrize('case', CASES, ids=CASE_IDS)
    def test_transcript_and_dh_match(self, case):
        assert hs.transcript_hash(
            unhex(case['server_public']), unhex(case['client_hello']),
            unhex(case['server_ephemeral_public'])) == \
            unhex(case['transcript_hash'])
        assert hs._x25519(unhex(case['client_ephemeral_private']),
                          unhex(case['server_ephemeral_public'])) == \
            unhex(case['dh_ee'])
        assert hs._x25519(unhex(case['client_ephemeral_private']),
                          unhex(case['server_public'])) == unhex(case['dh_es'])

    @pytest.mark.parametrize('case', CASES, ids=CASE_IDS)
    def test_key_schedule_matches(self, case):
        keys = hs.derive_session_keys(unhex(case['transcript_hash']),
                                      unhex(case['dh_ee']),
                                      unhex(case['dh_es']))
        for name, expected in case['keys'].items():
            assert getattr(keys, name) == unhex(expected), name
        assert hs.server_mac(keys, unhex(case['transcript_hash'])) == \
            unhex(case['server_mac'])

    @pytest.mark.parametrize('case', CASES, ids=CASE_IDS)
    def test_server_hello_bytes_match(self, case):
        _hello, reply, _keys = accept(case, unhex(case['client_hello']))
        assert reply == unhex(case['server_hello'])

    @pytest.mark.parametrize('case', CASES, ids=CASE_IDS)
    def test_both_ends_agree(self, case):
        client = client_for(case)
        _hello, reply, server_keys = accept(case, client.hello_bytes)
        client_keys = client.finish(reply)
        assert client_keys == server_keys
        for name, expected in case['keys'].items():
            assert getattr(client_keys, name) == unhex(expected), name

    def test_the_five_keys_are_distinct(self):
        case = CASES[0]
        keys = hs.derive_session_keys(unhex(case['transcript_hash']),
                                      unhex(case['dh_ee']),
                                      unhex(case['dh_es']))
        values = [getattr(keys, name) for name in keys.__slots__]
        assert len(set(values)) == len(values)

    def test_directions_do_not_share_keys(self):
        case = CASES[0]
        keys = hs.derive_session_keys(unhex(case['transcript_hash']),
                                      unhex(case['dh_ee']),
                                      unhex(case['dh_es']))
        assert keys.outgoing(is_client=True) == keys.incoming(is_client=False)
        assert keys.outgoing(is_client=False) == keys.incoming(is_client=True)
        assert keys.outgoing(is_client=True) != keys.outgoing(is_client=False)

    def test_session_keys_never_render_their_material(self):
        """A SessionKeys can reach a traceback or a log line."""
        case = CASES[0]
        keys = hs.derive_session_keys(unhex(case['transcript_hash']),
                                      unhex(case['dh_ee']),
                                      unhex(case['dh_es']))
        rendered = repr(keys)
        assert 'redacted' in rendered
        for value in case['keys'].values():
            assert value not in rendered


class TestClientHelloTampering:
    """Every field of the client hello, altered one at a time."""

    CASE = CASES[0]

    def hello(self):
        return bytearray(unhex(self.CASE['client_hello']))

    def test_untampered_is_accepted(self):
        accept(self.CASE, bytes(self.hello()))

    def test_version_byte(self):
        raw = self.hello()
        raw[0] = 0x02
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, bytes(raw))

    @pytest.mark.parametrize('bit', [0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80])
    def test_reserved_flag_bits(self, bit):
        raw = self.hello()
        raw[1] |= bit
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, bytes(raw))

    def test_mode_bit_flips_the_negotiated_mode(self):
        """Bit 0 is not tampering: it is how the client picks the mode, and it
        is bound into H, so a flip in flight breaks the MAC instead."""
        raw = self.hello()
        raw[1] ^= hs.FLAG_FORMAT_MODE
        hello, reply, _keys = accept(self.CASE, bytes(raw))
        assert hello.mode == 'format'
        # The honest client's key schedule is over its own hello, so the
        # flipped one produces a MAC it will not accept.
        with pytest.raises(hs.InvalidHello):
            client_for(self.CASE).finish(reply)

    def test_definitions_release(self):
        raw = self.hello()
        raw[2:6] = (self.CASE['defs'] + 1).to_bytes(4, 'big')
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, bytes(raw))

    def test_format_name_length(self):
        raw = self.hello()
        raw[6] = raw[6] + 1
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, bytes(raw))

    def test_zero_length_format_name(self):
        raw = self.hello()
        del raw[7:7 + raw[6]]
        raw[6] = 0
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, bytes(raw))

    def test_unknown_format_name(self):
        raw = bytearray(hs.ClientHello(
            mode=self.CASE['mode'], defs=self.CASE['defs'],
            format='no-such-format',
            client_public=unhex(self.CASE['client_ephemeral_public']),
            epoch=self.CASE['epoch']).encode())
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, bytes(raw))

    def test_non_ascii_format_name(self):
        raw = self.hello()
        raw[7] = 0xFF
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, bytes(raw))

    def test_client_public_key(self):
        """A substituted c_pub changes H, so the client cannot verify the
        reply: the connection fails rather than becoming a relay for a peer in
        the middle."""
        raw = self.hello()
        offset = 7 + raw[6]
        raw[offset] ^= 0x01
        _hello, reply, _keys = accept(self.CASE, bytes(raw))
        with pytest.raises(hs.InvalidHello):
            client_for(self.CASE).finish(reply)

    def test_epoch(self):
        raw = self.hello()
        raw[-4:] = (self.CASE['epoch'] + 5).to_bytes(4, 'big')
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, bytes(raw))

    def test_truncated(self):
        raw = self.hello()
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, bytes(raw[:-1]))

    def test_trailing_bytes(self):
        raw = self.hello()
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, bytes(raw) + b'\x00')

    def test_empty(self):
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, b'')


class TestServerHelloTampering:
    """Every field of the server hello, altered one at a time."""

    CASE = CASES[0]

    def reply(self):
        return bytearray(unhex(self.CASE['server_hello']))

    def test_untampered_is_accepted(self):
        client_for(self.CASE).finish(bytes(self.reply()))

    def test_version_byte(self):
        raw = self.reply()
        raw[0] = 0x02
        with pytest.raises(hs.InvalidHello):
            client_for(self.CASE).finish(bytes(raw))

    @pytest.mark.parametrize('bit', [0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80])
    def test_reserved_flag_bits(self, bit):
        raw = self.reply()
        raw[1] |= bit
        with pytest.raises(hs.InvalidHello):
            client_for(self.CASE).finish(bytes(raw))

    def test_mode_echo_must_match(self):
        raw = self.reply()
        raw[1] ^= hs.FLAG_FORMAT_MODE
        with pytest.raises(hs.InvalidHello):
            client_for(self.CASE).finish(bytes(raw))

    def test_server_ephemeral_key(self):
        raw = self.reply()
        raw[2] ^= 0x01
        with pytest.raises(hs.InvalidHello):
            client_for(self.CASE).finish(bytes(raw))

    @pytest.mark.parametrize('index', range(hs.MAC_BYTES))
    def test_every_mac_byte(self, index):
        raw = self.reply()
        raw[2 + hs.KEY_BYTES + index] ^= 0x01
        with pytest.raises(hs.InvalidHello):
            client_for(self.CASE).finish(bytes(raw))

    def test_truncated(self):
        raw = self.reply()
        with pytest.raises(hs.InvalidHello):
            client_for(self.CASE).finish(bytes(raw[:-1]))

    def test_trailing_bytes(self):
        raw = self.reply()
        with pytest.raises(hs.InvalidHello):
            client_for(self.CASE).finish(bytes(raw) + b'\x00')


class TestWrongServerKey:
    """Only the holder of the private key behind the server-id can reply."""

    CASE = CASES[0]

    def test_a_different_server_cannot_produce_the_mac(self):
        """An impostor holding the connection string can seal a reply -- the
        cover key is public to string holders -- but not one whose MAC
        verifies, because K_auth_s comes from DH_es."""
        impostor_private, _ = fteproxy.generate_server_key()
        client = client_for(self.CASE)
        _hello, reply, _keys = accept(
            self.CASE, client.hello_bytes, server_private=impostor_private)
        with pytest.raises(hs.InvalidHello):
            client.finish(reply)

    def test_a_client_with_the_wrong_server_id_derives_different_keys(self):
        _other_private, other_public = fteproxy.generate_server_key()
        client = hs.ClientHandshake(
            server_public=other_public, format=self.CASE['format'],
            mode=self.CASE['mode'], defs=self.CASE['defs'],
            epoch=self.CASE['epoch'],
            ephemeral_private=unhex(self.CASE['client_ephemeral_private']))
        _hello, reply, _keys = accept(self.CASE, client.hello_bytes)
        with pytest.raises(hs.InvalidHello):
            client.finish(reply)

    def test_all_zero_shared_secret_is_refused(self):
        """A small-order peer point would drive the shared secret to zero and
        let anyone who can rewrite the hellos fix both key schedules."""
        with pytest.raises(hs.InvalidHello):
            hs._x25519(unhex(self.CASE['client_ephemeral_private']),
                       b'\x00' * 32)


class TestEpoch:

    CASE = CASES[0]

    def hello_at(self, epoch):
        return hs.ClientHello(
            mode=self.CASE['mode'], defs=self.CASE['defs'],
            format=self.CASE['format'],
            client_public=unhex(self.CASE['client_ephemeral_public']),
            epoch=epoch).encode()

    @pytest.mark.parametrize('skew', [-1, 0, 1])
    def test_inside_the_window_is_accepted(self, skew):
        now = self.CASE['epoch']
        accept(self.CASE, self.hello_at(now + skew), now_epoch=now)

    @pytest.mark.parametrize('skew', [-2, 2, 24, -24])
    def test_outside_the_window_is_refused(self, skew):
        now = self.CASE['epoch']
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, self.hello_at(now + skew), now_epoch=now)

    def test_current_epoch_is_hours(self):
        assert hs.current_epoch(now=0) == 0
        assert hs.current_epoch(now=3599) == 0
        assert hs.current_epoch(now=3600) == 1
        assert hs.current_epoch(now=7200) == 2


class TestReplayFilter:

    CASE = CASES[0]

    def test_a_repeated_hello_is_refused(self):
        replay = hs.ReplayFilter()
        hello_bytes = unhex(self.CASE['client_hello'])
        accept(self.CASE, hello_bytes, replay=replay)
        with pytest.raises(hs.ReplayedHello):
            accept(self.CASE, hello_bytes, replay=replay)

    def test_a_fresh_ephemeral_key_is_accepted(self):
        replay = hs.ReplayFilter()
        accept(self.CASE, unhex(self.CASE['client_hello']), replay=replay)
        fresh = client_for(dict(self.CASE,
                                client_ephemeral_private=os.urandom(32).hex()))
        accept(self.CASE, fresh.hello_bytes, replay=replay)

    def test_a_key_outside_the_window_is_forgotten(self):
        """The window is what bounds the filter: past it a hello is refused on
        its epoch, so remembering the key buys nothing."""
        replay = hs.ReplayFilter()
        now = self.CASE['epoch']
        assert replay.observe(b'\x01' * 32, now, now)
        assert not replay.observe(b'\x01' * 32, now, now)
        assert replay.observe(b'\x01' * 32, now + 10, now + 10)

    def test_neighbouring_epochs_are_remembered(self):
        replay = hs.ReplayFilter()
        now = self.CASE['epoch']
        assert replay.observe(b'\x02' * 32, now - 1, now)
        assert not replay.observe(b'\x02' * 32, now, now)
        assert not replay.observe(b'\x02' * 32, now + 1, now)

    def test_the_filter_is_bounded(self):
        replay = hs.ReplayFilter(max_entries=64)
        now = 100
        for epoch in (now - 1, now, now + 1):
            for i in range(64):
                replay.observe(bytes([epoch % 256, i]) + b'\x00' * 30, epoch,
                               now)
        assert len(replay) <= 64 + 64

    def test_a_rejected_hello_does_not_enter_the_filter(self):
        """observe() runs last, so a hello refused for its epoch or format
        cannot be used to fill the filter and lock out a real client."""
        replay = hs.ReplayFilter()
        now = self.CASE['epoch']
        stale = hs.ClientHello(
            mode=self.CASE['mode'], defs=self.CASE['defs'],
            format=self.CASE['format'],
            client_public=unhex(self.CASE['client_ephemeral_public']),
            epoch=now + 12).encode()
        with pytest.raises(hs.InvalidHello):
            accept(self.CASE, stale, replay=replay, now_epoch=now)
        assert len(replay) == 0
        # The same ephemeral key still works at a valid epoch.
        accept(self.CASE, unhex(self.CASE['client_hello']), replay=replay,
               now_epoch=now)


class TestKeyGeneration:

    def test_keys_are_fresh(self):
        first_private, first_public = fteproxy.generate_server_key()
        second_private, second_public = fteproxy.generate_server_key()
        assert len(first_private) == 32 and len(first_public) == 32
        assert first_private != second_private
        assert first_public != second_public

    def test_public_half_is_derivable(self):
        private, public = fteproxy.generate_server_key()
        assert fteproxy.server_id(private) == public

    @pytest.mark.parametrize('bad', [b'', b'\x00' * 31, b'\x00' * 33, 'text'])
    def test_wrong_length_is_rejected(self, bad):
        with pytest.raises(ValueError):
            hs.server_id(bad)


class TestRejectDelay:

    def test_within_one_to_five_seconds(self):
        for _ in range(200):
            delay = hs.reject_delay()
            assert 1.0 <= delay <= 5.0

    def test_varies(self):
        assert len({hs.reject_delay() for _ in range(50)}) > 1
