#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for _FTESocketWrapper.recv() connection-close (EOF) semantics.

These exercise a gap in the existing suite: what recv() does when the peer
closes the TCP connection while undecodable bytes remain buffered in the
decoder (e.g. the peer was cut off part-way through a covertext cell).
"""

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


def _regex_length():
    return (fteproxy.defs.getRegex(FORMAT), fteproxy.defs.getLength(FORMAT))


def _make_cell(payload):
    """Encode ``payload`` into one covertext record-layer cell."""
    pattern, length = _regex_length()
    key = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')
    header = fteproxy._make_cipher(pattern, length, key)
    # Build through _record_encoder so the cell matches the configured mode (the
    # wrapper under test decodes with whatever mode conf says).
    encoder = fteproxy._record_encoder(header, key)
    encoder.push(payload)
    return encoder.pop()


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
        import socket
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


class CapturingSocket(FakeSocket):
    """A FakeSocket that also records everything the wrapper sends."""

    def __init__(self, chunks=()):
        super().__init__(chunks)
        self.sent = []

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def sendall(self, data):
        self.sent.append(data)


@pytest.fixture(params=['hybrid', 'format'])
def record_layer_mode(request):
    key = 'runtime.fteproxy.record_layer.mode'
    prev = fteproxy.conf.getValue(key)
    fteproxy.conf.setValue(key, request.param)
    yield request.param
    fteproxy.conf.setValue(key, prev)


def _client_wire(payload):
    """What a negotiating client puts on the wire to send ``payload``: the
    negotiation record, then the first data record, as two byte strings."""
    up = fteproxy.conf.getValue('runtime.state.upstream_language')
    down = fteproxy.conf.getValue('runtime.state.downstream_language')
    sock = CapturingSocket()
    client = fteproxy.wrap_socket(
        sock,
        outgoing_regex=fteproxy.defs.getRegex(up),
        outgoing_length=fteproxy.defs.getLength(up),
        incoming_regex=fteproxy.defs.getRegex(down),
        incoming_length=fteproxy.defs.getLength(down))
    client.send(payload)
    negotiation, data = sock.sent
    return negotiation, data


class TestNegotiationRecordReplay:
    """The negotiation cell is record 0 of the client's stream, so a duplicated
    negotiation record is rejected like any other replayed record.

    Regression tests. The client used to encode the negotiation cell with a
    throw-away encoder and the server to decode it with a throw-away decoder,
    so the cell and the first data record were both sealed at seq 0. A stream
    ``[nego][nego][data0]`` then delivered the second cell's 64-byte plaintext
    to the destination as application data before stalling on ``data0``.
    """

    def test_first_data_record_is_sealed_at_seq_1(self, record_layer_mode):
        """On the wire, the negotiation record is seq 0 and data starts at 1."""
        negotiation, data = _client_wire(b'payload')
        up = fteproxy.conf.getValue('runtime.state.upstream_language')
        key = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')
        cipher = fteproxy._make_cipher(
            fteproxy.defs.getRegex(up), fteproxy.defs.getLength(up), key)

        decoder = fteproxy._record_decoder(cipher, key)
        decoder.push(negotiation + data)
        cell = fteproxy.NegotiateCell().fromBytes(decoder.pop(oneCell=True))
        assert cell.getLanguage() == up[:-len('-request')]
        assert decoder.pop() == b'payload'
        assert decoder._seq == 2

        # The data record alone does not unseal at position 0.
        fresh = fteproxy._record_decoder(cipher, key)
        fresh.push(data)
        assert fresh.pop() == b''

    def test_server_continues_stream_after_negotiation(self, record_layer_mode):
        """The server's data decoder carries on from the negotiation cell."""
        negotiation, data = _client_wire(b'payload')
        for chunks in ([negotiation + data], [negotiation, data]):
            server = fteproxy.wrap_socket(FakeSocket(chunks))
            assert server.recv(65536) == b'payload'
            assert server._decoder._seq == 2

    def test_duplicated_negotiation_record_delivers_nothing(self, record_layer_mode):
        negotiation, data = _client_wire(b'payload')
        for chunks in ([negotiation + negotiation + data],
                       [negotiation, negotiation + data]):
            server = fteproxy.wrap_socket(FakeSocket(chunks))
            # Negotiation succeeds on the first cell. The duplicate is then a
            # record out of its stream position, so nothing decodes and the
            # stream stops: recv() reports EOF once the peer is gone, having
            # delivered no application data (not the cell's plaintext, and
            # not data0, which is sealed at seq 1).
            assert server.recv(65536) == b''
            assert server._negotiationComplete
            assert server._decoder._seq == 1
            assert server._decoder._buffer == negotiation + data
