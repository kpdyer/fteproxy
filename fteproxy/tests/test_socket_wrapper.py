#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for _FTESocketWrapper.recv() connection-close (EOF) semantics.

These exercise a gap in the existing suite: what recv() does when the peer
closes the TCP connection while undecodable bytes remain buffered in the
decoder (e.g. the peer was cut off part-way through a covertext cell), and
what it does with a peer that keeps sending bytes that can never decode.
"""

import os
import socket

import pytest

import fteproxy
import fteproxy.conf
import fteproxy.defs
import fteproxy.record_layer


FORMAT = 'manual-http-request'


@pytest.fixture(autouse=True)
def _defs():
    fteproxy.conf.setValue('runtime.mode', 'client')
    fteproxy.defs.load_definitions()


def _regex_length(language=FORMAT):
    return (fteproxy.defs.getRegex(language), fteproxy.defs.getLength(language))


def _make_cell(payload, language=FORMAT):
    """Encode ``payload`` into one covertext record-layer cell."""
    pattern, length = _regex_length(language)
    key = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')
    header = fteproxy._make_cipher(pattern, length, key)
    # Build through _record_encoder so the cell matches the configured mode (the
    # wrapper under test decodes with whatever mode conf says).
    encoder = fteproxy._record_encoder(header, key)
    encoder.push(payload)
    return encoder.pop()


def _negotiation_record(language=FORMAT):
    """The record an fteproxy client opens a ``language`` stream with."""
    previous = fteproxy.conf.getValue('runtime.state.upstream_language')
    fteproxy.conf.setValue('runtime.state.upstream_language', language)
    try:
        response = language[:-len('-request')] + '-response'
        manager = fteproxy.NegotiationManager(None, None)
        return manager.makeClientNegotiationCell(
            *_regex_length(language), *_regex_length(response))
    finally:
        fteproxy.conf.setValue('runtime.state.upstream_language', previous)


class FakeSocket:
    """A minimal socket stand-in.

    Yields the queued ``chunks`` from recv() and then returns b'' forever,
    which is exactly how a real TCP socket behaves once the peer has closed
    the connection (recv() returns b'' on every subsequent call). ``spin_cap``
    turns an accidental infinite read loop into a fast, deterministic failure
    instead of hanging the test process.
    """

    def __init__(self, chunks, spin_cap=5000):
        self._chunks = list(chunks)
        self._spin_cap = spin_cap
        self.eof_reads = 0

    def recv(self, _bufsize):
        if self._chunks:
            return self._chunks.pop(0)
        self.eof_reads += 1
        if self.eof_reads > self._spin_cap:
            raise AssertionError(
                "recv() spun on a closed socket %d times without returning "
                "EOF" % self.eof_reads)
        return b''

    # send()/sendall() are only reached during negotiation; unused here since
    # these tests wrap with negotiate=False.
    def send(self, data):
        return len(data)

    def sendall(self, data):
        return None


def _wrap(fake):
    regex, length = _regex_length()
    return fteproxy.wrap_socket(
        fake,
        outgoing_regex=regex, outgoing_length=length,
        incoming_regex=regex, incoming_length=length,
        negotiate=False)


class TestServerNegotiationEOF:
    """A server-role wrapper whose peer closes before negotiating reports EOF.

    Regression test for a relay worker leak: a failed negotiation used to raise
    ``socket.timeout`` ("not ready yet") even after the peer had closed, so the
    worker re-polled a closed socket at the throttle rate forever. Under libfte
    0.4 every mismatched peer (a 0.3 client, a wrong key, a wrong
    --record-layer-mode, a port scanner) takes this path.
    """

    def _server_wrap(self, fake):
        return fteproxy.wrap_socket(fake)  # no formats given: server role

    def test_close_without_data_returns_eof(self):
        fake = FakeSocket([])
        assert self._server_wrap(fake).recv(65536) == b''
        assert fake.eof_reads == 1

    def test_garbage_then_close_returns_eof(self):
        fake = FakeSocket([b'not a negotiation cell'])
        wrapper = self._server_wrap(fake)
        with pytest.raises(socket.timeout):  # cell incomplete: keep waiting
            wrapper.recv(65536)
        assert wrapper.recv(65536) == b''    # peer gone: EOF, not another wait
        assert fake.eof_reads == 1


class TestRecvEOF:
    """recv() must report EOF (return b'') once the peer has closed."""

    def test_clean_eof_returns_empty(self):
        """Peer closes with nothing buffered -> recv() returns b''."""
        wrapper = _wrap(FakeSocket([]))
        assert wrapper.recv(65536) == b''

    def test_complete_cell_then_eof(self):
        """A full cell is delivered, then recv() reports EOF on the next call."""
        wrapper = _wrap(FakeSocket([_make_cell(b'hello')]))
        assert wrapper.recv(65536) == b'hello'
        assert wrapper.recv(65536) == b''

    def test_truncated_cell_after_close_returns_eof(self):
        """Peer closes mid-cell (truncated covertext left in the buffer).

        The leftover bytes can never form a complete cell because the peer is
        gone, so recv() must return b'' (EOF) rather than busy-looping on a
        closed socket forever.
        """
        truncated = _make_cell(b'hello')[:-3]
        fake = FakeSocket([truncated])
        wrapper = _wrap(fake)
        assert wrapper.recv(65536) == b''

    def test_good_cell_then_truncated_tail_then_eof(self):
        """Decode the good cell, then report EOF for the truncated tail."""
        good = _make_cell(b'hello')
        truncated_tail = _make_cell(b'world')[:-3]
        fake = FakeSocket([good + truncated_tail])
        wrapper = _wrap(fake)
        assert wrapper.recv(65536) == b'hello'
        assert wrapper.recv(65536) == b''


class TestServerNegotiationCap:
    """A peer that never negotiates cannot make the server hoard its bytes.

    Regression tests for a memory exhaustion: the server used to append every
    byte an unauthenticated peer sent to its pre-negotiation buffer and rescan
    the whole buffer against every request format on each read, so one
    connection sending 100 MB of garbage grew the process past 5 GB. Only the
    first negotiation-record's worth of bytes can ever decode, so that is all
    the wrapper keeps or scans, and past it the peer is refused.
    """

    def _server_wrap(self, fake):
        return fteproxy.wrap_socket(fake)  # no formats given: server role

    def _cap(self, wrapper):
        return wrapper._negotiation_manager.getMaxNegotiationBytes()

    def test_cap_is_the_longest_negotiation_record(self):
        """The bound is exactly the record of the longest built-in request
        format ('binary-request', 1032 bytes), so nothing valid is refused."""
        cap = self._cap(self._server_wrap(FakeSocket([])))
        assert cap == len(_negotiation_record('binary-request'))
        assert cap >= len(_negotiation_record(FORMAT))

    def test_garbage_past_the_cap_returns_eof_and_stops_reading(self, capsys):
        small = [os.urandom(200) for _ in range(20)]
        big = [os.urandom(256 * 1024) for _ in range(4)]
        fake = FakeSocket(small + big)
        wrapper = self._server_wrap(fake)
        cap = self._cap(wrapper)

        waits = 0
        while True:
            try:
                out = wrapper.recv(2 ** 18)
                break
            except socket.timeout:              # a record may still be coming
                waits += 1
                assert len(wrapper._preNegotiationBuffer_incoming) <= cap
        assert out == b''
        assert 'closing connection: negotiation failed' in capsys.readouterr().out

        # It gave up on the first read that took it past one record's worth...
        consumed = sum(map(len, small + big)) - sum(map(len, fake._chunks))
        assert cap < consumed <= cap + 200
        assert waits == consumed // 200 - 1
        assert wrapper._preNegotiationBuffer_incoming == b''
        # ...and reads nothing more from the socket afterwards.
        assert wrapper.recv(2 ** 18) == b''
        assert len(fake._chunks) == len(small + big) - consumed // 200
        assert fake.eof_reads == 0

    def test_one_large_garbage_read_returns_eof(self):
        """The relay reads 256 KiB at a time; a single such read of garbage is
        refused outright rather than buffered."""
        fake = FakeSocket([os.urandom(256 * 1024)] * 3)
        wrapper = self._server_wrap(fake)
        assert wrapper.recv(2 ** 18) == b''
        assert wrapper._preNegotiationBuffer_incoming == b''
        assert len(fake._chunks) == 2

    def test_record_filling_the_cap_still_negotiates(self):
        """The cap is exact: a negotiation record of the longest format is
        exactly cap bytes and, arriving a byte short and then complete, is
        accepted rather than refused."""
        language = 'binary-request'
        cell = _negotiation_record(language)
        data = _make_cell(b'hello', language)
        fake = FakeSocket([cell[:-1], cell[-1:], data])
        wrapper = self._server_wrap(fake)
        assert len(cell) == self._cap(wrapper)

        with pytest.raises(socket.timeout):     # one byte short of a record
            wrapper.recv(2 ** 18)
        assert len(wrapper._preNegotiationBuffer_incoming) == len(cell) - 1
        assert wrapper.recv(2 ** 18) == b'hello'
        assert wrapper._negotiationComplete
        assert fake.eof_reads == 0

    def test_bytes_past_the_record_open_the_stream(self):
        """Only the first cap bytes are scanned; data behind them in the same
        read (and behind the record inside the scanned prefix) is fed to the
        negotiated decoder, not lost."""
        cell = _negotiation_record()
        payload = os.urandom(3000)
        data = _make_cell(payload)
        fake = FakeSocket([cell + data])
        wrapper = self._server_wrap(fake)
        assert len(cell) + len(data) > self._cap(wrapper)
        assert wrapper.recv(2 ** 18) == payload
        assert wrapper._preNegotiationBuffer_incoming == b''

    def test_garbage_after_negotiation_returns_eof(self):
        """A replayed negotiation record followed by garbage is cut off at the
        first frame that fails, instead of accumulating for the connection's
        lifetime."""
        fake = FakeSocket([_negotiation_record()] + [os.urandom(256 * 1024)] * 4)
        wrapper = self._server_wrap(fake)
        assert wrapper.recv(2 ** 18) == b''
        assert wrapper._negotiationComplete
        assert wrapper._decoder.failed
        assert wrapper._decoder._buffer == b''
        assert wrapper.recv(2 ** 18) == b''
        assert len(fake._chunks) == 3               # nothing more was read
        assert fake.eof_reads == 0


class TestRecvAuthFailure:
    """Once a record fails authentication, recv() reports EOF and the wrapper
    reads nothing more: the decoder can never resume, so buffering later bytes
    would only grow without bound."""

    def test_bad_record_after_good_one(self, capsys):
        good = _make_cell(b'hello')
        bad = bytearray(_make_cell(b'world'))
        bad[-1] ^= 0x01
        fake = FakeSocket([good, bytes(bad), os.urandom(65536), os.urandom(65536)])
        wrapper = _wrap(fake)
        assert wrapper.recv(65536) == b'hello'
        assert wrapper.recv(65536) == b''
        assert 'a record failed authentication' in capsys.readouterr().out
        assert wrapper._decoder.failed
        assert wrapper._decoder._buffer == b''
        assert wrapper.recv(65536) == b''
        assert len(fake._chunks) == 2
        assert fake.eof_reads == 0

    def test_good_and_bad_in_one_read(self):
        """What decoded before the bad record is delivered, then EOF."""
        good = _make_cell(b'hello')
        bad = bytearray(_make_cell(b'world'))
        bad[-1] ^= 0x01
        fake = FakeSocket([good + bytes(bad), os.urandom(65536)])
        wrapper = _wrap(fake)
        assert wrapper.recv(65536) == b'hello'
        assert wrapper.recv(65536) == b''
        assert len(fake._chunks) == 1
        assert fake.eof_reads == 0

    def test_garbage_stream_is_dropped_at_the_first_read(self):
        chunks = [os.urandom(256 * 1024) for _ in range(4)]
        fake = FakeSocket(list(chunks))
        wrapper = _wrap(fake)
        assert wrapper.recv(2 ** 18) == b''
        assert wrapper._decoder._buffer == b''
        assert len(fake._chunks) == 3
