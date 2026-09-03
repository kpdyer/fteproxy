#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for ``_FTESocketWrapper``: EOF semantics and the reject path.

The EOF cases exercise what ``recv()`` does when the peer closes the TCP
connection while undecodable bytes remain buffered (the peer was cut off
part-way through a covertext), and what the server does with a first record it
cannot validate. Both are places where returning "not ready yet" instead of
EOF used to leave a relay worker polling a dead socket forever.
"""

import socket
import time

import pytest

import fteproxy
import fteproxy.conf
import fteproxy.defs
import fteproxy.handshake
import fteproxy.record_layer


FORMAT = 'manual-http'
MODE = 'hybrid'

SERVER_PRIVATE, SERVER_PUBLIC = fteproxy.generate_server_key()


@pytest.fixture(autouse=True)
def _defs():
    fteproxy.defs.load_definitions()


def _session_keys():
    """Deterministic session keys, standing in for a completed handshake."""
    return fteproxy.handshake.derive_session_keys(
        transcript=b'\x01' * 32, dh_ee=b'\x02' * 32, dh_es=b'\x03' * 32)


def _completed(sock, keys, is_client, mode=MODE):
    """A wrapper with the handshake already done, so a test can drive the
    session stream without standing up a second endpoint."""
    if is_client:
        wrapper = fteproxy.wrap_socket(sock, server_id=SERVER_PUBLIC,
                                       format=FORMAT, mode=mode)
    else:
        wrapper = fteproxy.wrap_socket(sock, server_key=SERVER_PRIVATE)
    wrapper._encoder, wrapper._decoder = fteproxy._session_channel(
        FORMAT, mode, keys, is_client=is_client)
    wrapper._handshake_done = True
    wrapper._negotiated_format = FORMAT
    wrapper._negotiated_mode = mode
    return wrapper


class FakeSocket:
    """A minimal socket stand-in.

    Yields the queued ``chunks`` from recv() and then returns b'' forever,
    which is exactly how a real TCP socket behaves once the peer has closed
    the connection (recv() returns b'' on every subsequent call). ``spin_cap``
    turns an accidental infinite read loop into a fast, deterministic failure
    instead of hanging the test process.
    """

    def __init__(self, chunks=(), spin_cap=5000):
        self._chunks = list(chunks)
        self._spin_cap = spin_cap
        self.eof_reads = 0
        self.sent = b''
        self.timeout = None

    def recv(self, _bufsize):
        if self._chunks:
            return self._chunks.pop(0)
        self.eof_reads += 1
        if self.eof_reads > self._spin_cap:
            raise AssertionError(
                "recv() spun on a closed socket %d times without returning "
                "EOF" % self.eof_reads)
        return b''

    def send(self, data):
        self.sent += data
        return len(data)

    def sendall(self, data):
        self.sent += data

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value


class SilentSocket(FakeSocket):
    """A peer that stays connected but says nothing more.

    Once its queued chunks run out, recv() honours the socket timeout and
    raises, as a real socket does, instead of reporting EOF. This is what an
    active prober looks like: it does not hang up when it gets no answer.
    """

    def __init__(self, chunks=()):
        super().__init__(chunks)
        self.reads = 0

    def recv(self, _bufsize):
        self.reads += 1
        if self._chunks:
            return self._chunks.pop(0)
        time.sleep(self.timeout if self.timeout else 0.01)
        raise socket.timeout()


class TestServerHandshakeEOF:
    """A server whose peer closes before a hello decodes reports EOF.

    Regression test for a relay worker leak: a failed handshake that raised
    ``socket.timeout`` ("not ready yet") after the peer had closed left the
    worker re-polling a closed socket at the throttle rate forever. Every
    mismatched peer -- a 0.3 client, a wrong connection string, a port
    scanner -- takes this path.
    """

    def test_close_without_data_returns_eof(self):
        fake = FakeSocket()
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        assert server.recv(65536) == b''
        assert fake.eof_reads == 1
        assert fake.sent == b''

    def test_garbage_then_close_returns_eof(self):
        fake = FakeSocket([b'not a client hello'])
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        assert server.recv(65536) == b''
        assert fake.sent == b'', 'the server must never reply to a bad hello'


class TestServerRejectPath:
    """A hello that decodes but does not validate is answered with silence."""

    def _hello_for(self, **overrides):
        settings = dict(server_public=SERVER_PUBLIC, format=FORMAT,
                        mode=MODE, defs=20260110)
        settings.update(overrides)
        return fteproxy.handshake.ClientHandshake(**settings)

    def _seal(self, hello_bytes, cover_key):
        cipher = fteproxy._cipher_for(FORMAT + '-request', cover_key,
                                      cover=True)
        return fteproxy.record_layer._seal(cipher, hello_bytes, 0)

    def test_stale_epoch_gets_no_reply(self, monkeypatch):
        monkeypatch.setattr(fteproxy.handshake, 'reject_delay', lambda: 0.05)
        driver = self._hello_for(epoch=fteproxy.handshake.current_epoch() - 48)
        sealed = self._seal(driver.hello_bytes,
                            fteproxy.handshake.cover_key(SERVER_PUBLIC))
        fake = FakeSocket([sealed])
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        assert server.recv(65536) == b''
        assert fake.sent == b''

    def test_wrong_cover_key_gets_no_reply(self, monkeypatch):
        """A hello sealed for a different server never decodes here, so the
        server waits out its handshake deadline and then discards."""
        monkeypatch.setattr(fteproxy.handshake, 'reject_delay', lambda: 0.05)
        previous = fteproxy.conf.getValue('runtime.fteproxy.handshake.timeout')
        fteproxy.conf.setValue('runtime.fteproxy.handshake.timeout', 0.2)
        try:
            _other_private, other_public = fteproxy.generate_server_key()
            driver = self._hello_for(server_public=other_public)
            sealed = self._seal(driver.hello_bytes,
                                fteproxy.handshake.cover_key(other_public))
            # The peer stays connected but silent after its bad hello.
            fake = FakeSocket([sealed], spin_cap=10 ** 6)
            server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
            assert server.recv(65536) == b''
            assert fake.sent == b''
        finally:
            fteproxy.conf.setValue('runtime.fteproxy.handshake.timeout',
                                   previous)

    def test_reject_discards_for_a_while_before_closing(self, monkeypatch):
        """obfs4's behaviour: the connection stays open, reading and
        discarding, so a prober that stays connected cannot time the failure
        or tell it from a service with nothing to say."""
        monkeypatch.setattr(fteproxy.handshake, 'reject_delay', lambda: 0.25)
        driver = self._hello_for(epoch=0)
        sealed = self._seal(driver.hello_bytes,
                            fteproxy.handshake.cover_key(SERVER_PUBLIC))
        fake = SilentSocket([sealed])
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        started = time.monotonic()
        assert server.recv(65536) == b''
        assert time.monotonic() - started >= 0.2
        assert fake.sent == b''
        assert fake.reads > 1, 'the connection was read, not just held open'

    def test_replayed_hello_gets_no_reply(self, monkeypatch):
        monkeypatch.setattr(fteproxy.handshake, 'reject_delay', lambda: 0.05)
        driver = self._hello_for()
        sealed = self._seal(driver.hello_bytes,
                            fteproxy.handshake.cover_key(SERVER_PUBLIC))

        first = FakeSocket([sealed])
        assert fteproxy.wrap_socket(
            first, server_key=SERVER_PRIVATE).recv(65536) == b''
        assert first.sent, 'the first hello is answered'

        second = FakeSocket([sealed])
        assert fteproxy.wrap_socket(
            second, server_key=SERVER_PRIVATE).recv(65536) == b''
        assert second.sent == b'', 'the replay is not'


class TestRecvEOF:
    """recv() must report EOF (return b'') once the peer has closed."""

    def _peer_records(self, *payloads):
        """Wire bytes as the *other* end of this session would produce them."""
        keys = _session_keys()
        peer = _completed(FakeSocket(), keys, is_client=False)
        wire = b''
        for payload in payloads:
            peer._encoder.push(payload)
            wire += peer._encoder.pop()
        return wire

    def _wrap(self, chunks):
        fake = FakeSocket(chunks)
        return fake, _completed(fake, _session_keys(), is_client=True)

    def test_clean_eof_returns_empty(self):
        _fake, wrapper = self._wrap([])
        assert wrapper.recv(65536) == b''

    def test_complete_record_then_eof(self):
        _fake, wrapper = self._wrap([self._peer_records(b'hello')])
        assert wrapper.recv(65536) == b'hello'
        assert wrapper.recv(65536) == b''

    def test_truncated_record_after_close_returns_eof(self):
        """Peer closes mid-record, so the leftover bytes can never complete."""
        _fake, wrapper = self._wrap([self._peer_records(b'hello')[:-3]])
        assert wrapper.recv(65536) == b''

    def test_good_record_then_truncated_tail_then_eof(self):
        wire = self._peer_records(b'hello') + self._peer_records(b'world')[:-3]
        _fake, wrapper = self._wrap([wire])
        assert wrapper.recv(65536) == b'hello'
        assert wrapper.recv(65536) == b''


class TestControlRecords:
    """CLOSE and the other types reach the caller, not the byte stream."""

    def _peer(self):
        keys = _session_keys()
        peer = _completed(FakeSocket(), keys, is_client=False)
        return keys, peer

    def test_close_record_is_eof_for_the_data_stream(self):
        keys, peer = self._peer()
        peer._encoder.push(b'last bytes')
        wire = peer._encoder.pop() + peer._encoder.encode(
            fteproxy.record_layer.CLOSE)
        fake = FakeSocket([wire], spin_cap=10)
        wrapper = _completed(fake, keys, is_client=True)
        assert wrapper.recv(65536) == b'last bytes'
        assert wrapper.recv(65536) == b''
        assert wrapper.peer_closed
        # EOF came from the record, not from a closed socket.
        assert fake.eof_reads == 0

    def test_control_records_are_queued(self):
        keys, peer = self._peer()
        wire = peer._encoder.encode(fteproxy.record_layer.OPEN, b'dest')
        peer._encoder.push(b'bytes')
        wire += peer._encoder.pop()
        fake = FakeSocket([wire])
        wrapper = _completed(fake, keys, is_client=True)
        assert wrapper.recv(65536) == b'bytes'
        assert wrapper.next_control_record() == (
            fteproxy.record_layer.OPEN, b'dest')
        assert wrapper.next_control_record() is None

    def test_padding_is_ignored(self):
        keys, peer = self._peer()
        wire = peer._encoder.encode(fteproxy.record_layer.PADDING, b'\x00' * 8)
        peer._encoder.push(b'bytes')
        wire += peer._encoder.pop()
        fake = FakeSocket([wire])
        wrapper = _completed(fake, keys, is_client=True)
        assert wrapper.recv(65536) == b'bytes'
        assert wrapper.next_control_record() is None

    def test_unknown_type_closes_the_connection(self):
        keys, peer = self._peer()
        fake = FakeSocket([peer._encoder._emit(0x7f, b'future')], spin_cap=10)
        wrapper = _completed(fake, keys, is_client=True)
        assert wrapper.recv(65536) == b''


class TestServerBuffersBeforeTheHandshake:
    """A destination that speaks first (an SSH or SMTP banner) is held until
    the client's hello arrives, rather than crashing on a missing encoder."""

    def test_send_before_the_handshake_is_buffered(self):
        fake = FakeSocket()
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        assert server.send(b'SSH-2.0-banner') == len(b'SSH-2.0-banner')
        assert fake.sent == b''
        assert server._pre_handshake_outgoing == b'SSH-2.0-banner'

    def test_the_buffer_is_bounded(self):
        fake = FakeSocket()
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        with pytest.raises(fteproxy.ChannelNotReadyException):
            server.send(b'x' * (server._MAX_PRE_HANDSHAKE_BYTES + 1))


class TestPreProtocolClient:
    """A client speaking the pre-1.0 shared-key negotiation gets no reply.

    On master the first record was a 64-byte cell sealed under a static shared
    key, with no version, no keypair and no epoch. There is no compatibility
    path (plan decision D1), so such a client must look exactly like any other
    peer the server cannot validate: silence.
    """

    LEGACY_KEY = b'\xFF' * 16 + b'\x00' * 16
    LEGACY_CELL = b'\x00' * 32 + b'20260110' + b'manual-http'

    def test_no_reply_and_one_debug_line(self, monkeypatch, caplog):
        import logging

        monkeypatch.setattr(fteproxy.handshake, 'reject_delay', lambda: 0.05)
        previous = fteproxy.conf.getValue('runtime.fteproxy.handshake.timeout')
        fteproxy.conf.setValue('runtime.fteproxy.handshake.timeout', 0.2)
        try:
            cipher = fteproxy._make_cipher(
                fteproxy.defs.getRegex(FORMAT + '-request'),
                fteproxy.defs.getLength(FORMAT + '-request'),
                self.LEGACY_KEY)
            cell = self.LEGACY_CELL.rjust(64, b'\x00')
            sealed = fteproxy.record_layer._seal(cipher, cell, 0)
            fake = SilentSocket([sealed])
            server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
            with caplog.at_level(logging.DEBUG, logger='fteproxy'):
                assert server.recv(65536) == b''
        finally:
            fteproxy.conf.setValue('runtime.fteproxy.handshake.timeout',
                                   previous)
        assert fake.sent == b''
        rejections = [record for record in caplog.records
                      if 'rejecting handshake without reply' in record.message]
        assert len(rejections) == 1
        assert rejections[0].levelno == logging.DEBUG


class TestFormatAgreement:
    """The covertext format and the name inside the hello must agree."""

    def _sealed(self, covertext_format, declared_format):
        """A hello sealed as ``covertext_format`` but naming ``declared_format``."""
        cover = fteproxy.handshake.cover_key(SERVER_PUBLIC)
        driver = fteproxy.handshake.ClientHandshake(
            server_public=SERVER_PUBLIC, format=declared_format, mode=MODE,
            defs=int(fteproxy.conf.getValue('fteproxy.defs.release')))
        cipher = fteproxy._cipher_for(covertext_format + '-request', cover,
                                      cover=True)
        return fteproxy.record_layer._seal(cipher, driver.hello_bytes, 0)

    def test_a_mismatched_name_gets_no_reply(self, monkeypatch):
        monkeypatch.setattr(fteproxy.handshake, 'reject_delay', lambda: 0.05)
        fake = FakeSocket([self._sealed('manual-http', 'words')])
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        assert server.recv(65536) == b''
        assert fake.sent == b''

    def test_an_unknown_name_gets_no_reply(self, monkeypatch):
        monkeypatch.setattr(fteproxy.handshake, 'reject_delay', lambda: 0.05)
        fake = FakeSocket([self._sealed('manual-http', 'no-such-format')])
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        assert server.recv(65536) == b''
        assert fake.sent == b''

    def test_two_names_sharing_a_pattern_both_work(self, monkeypatch):
        """A definitions file may give two base names the same pattern and
        length; then either one unseals the other's covertext, and the name
        inside the hello is what decides."""
        definitions = dict(fteproxy.defs.load_definitions())
        pattern = fteproxy.defs.getRegex('manual-http-request')
        response = fteproxy.defs.getRegex('manual-http-response')
        definitions['twin-request'] = {'regex': pattern}
        definitions['twin-response'] = {'regex': response}
        monkeypatch.setattr(fteproxy.defs, '_definitions', definitions)
        monkeypatch.setattr(fteproxy, '_last_matched_format',
                            'manual-http-request')

        fake = FakeSocket([self._sealed('manual-http', 'twin')])
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        server.handshake()
        assert server.negotiated_format == 'twin'
        assert fake.sent, 'the server answered'
