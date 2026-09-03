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


class RecordingSocket(FakeSocket):
    """A FakeSocket that records what was sent and how it was shut down."""

    def __init__(self, chunks=()):
        super().__init__(chunks)
        self.sent = []
        self.shutdowns = []

    def send(self, data):
        self.sent.append(bytes(data))
        return len(data)

    def sendall(self, data):
        self.sent.append(bytes(data))

    def shutdown(self, flags):
        self.shutdowns.append(flags)


class TestClientShutdownFlushesNegotiation:
    """``shutdown(SHUT_WR)`` on a client wrapper that has not sent anything yet
    must put the negotiation cell on the wire before the FIN.

    The relay half-closes the upstream socket when the application half-closes
    without sending; negotiation is in-band with the first send/recv, so
    without this the server would see EOF on an un-negotiated stream.
    """

    def _client_wrap(self, fake):
        regex, length = _regex_length()
        return fteproxy.wrap_socket(
            fake,
            outgoing_regex=regex, outgoing_length=length,
            incoming_regex=regex, incoming_length=length)

    def test_shut_wr_sends_negotiation_cell_first(self):
        import socket
        fake = RecordingSocket()
        sock = self._client_wrap(fake)
        sock.shutdown(socket.SHUT_WR)
        assert len(fake.sent) == 1, "negotiation cell was not flushed before FIN"
        assert fake.shutdowns == [socket.SHUT_WR]
        # Nothing more to negotiate on a later send: the cell goes out once.
        sock.send(b'late')
        assert len(fake.sent) == 2

    def test_shut_rd_does_not_negotiate(self):
        import socket
        fake = RecordingSocket()
        sock = self._client_wrap(fake)
        sock.shutdown(socket.SHUT_RD)
        assert fake.sent == []
        assert fake.shutdowns == [socket.SHUT_RD]

    def test_shut_wr_after_send_does_not_renegotiate(self):
        import socket
        fake = RecordingSocket()
        sock = self._client_wrap(fake)
        sock.send(b'request-body')
        sent_before = len(fake.sent)
        sock.shutdown(socket.SHUT_WR)
        assert len(fake.sent) == sent_before
        assert fake.shutdowns == [socket.SHUT_WR]
