#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test wrapper EOF, handshake rejection, framing, and resource bounds.

Truncated input followed by EOF must terminate instead of leaving a relay
polling a closed socket. Rejection tests check silence and deadlines anchored
to socket wrapping time, using deterministic clocks and real loopback sockets.
"""

import collections
import itertools
import os
import socket
import threading
import time

import pytest

import fteproxy
import fteproxy.conf
import fteproxy.defs
import fteproxy.handshake
import fteproxy.record_layer


#: These tests drive the wrapper against the comprehensive *shape* catalog:
#: ``manual-http`` is its HTTP-shaped entry, the pre-1.0 negotiation cell below
#: names that release, and one test synthesises a twin of a shape entry. The
#: catalog stopped being the shipped default when the 20260903 cleartext-
#: protocol release landed, so it is selected by name here rather than
#: inherited.
SHAPE_CATALOG = '20260110'

FORMAT = 'manual-http'
MODE = 'hybrid'

SERVER_PRIVATE, SERVER_PUBLIC = fteproxy.generate_server_key()


@pytest.fixture(autouse=True)
def _defs():
    """Select the shape catalog for this module, and put it back afterwards."""
    previous = fteproxy.conf.getValue('fteproxy.defs.release')
    fteproxy.conf.setValue('fteproxy.defs.release', SHAPE_CATALOG)
    fteproxy.defs.load_definitions()
    yield
    fteproxy.conf.setValue('fteproxy.defs.release', previous)


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


def _client_driver(**overrides):
    """A :class:`ClientHandshake` aimed at this module's server key."""
    settings = dict(server_public=SERVER_PUBLIC, format=FORMAT, mode=MODE,
                    defs=int(SHAPE_CATALOG))
    settings.update(overrides)
    return fteproxy.handshake.ClientHandshake(**settings)


def _seal_hello(hello_bytes, cover_key=None, covertext_format=FORMAT):
    """One client hello sealed as it goes on the wire."""
    if cover_key is None:
        cover_key = fteproxy.handshake.cover_key(SERVER_PUBLIC)
    cipher = fteproxy._cipher_for(covertext_format + '-request', cover_key,
                                  cover=True)
    return fteproxy.record_layer._seal(cipher, hello_bytes, 0)


def _sealed_hello(**overrides):
    """A fresh, valid, sealed client hello for this module's server."""
    return _seal_hello(_client_driver(**overrides).hello_bytes)


def _short_handshake_timeout(monkeypatch, seconds):
    """Shorten the handshake timeout, restored when the test ends.

    Worth doing in any test that waits for a rejection: the reject deadline is
    anchored to the accept and spans the whole handshake timeout, so the
    default five seconds is five seconds of test.
    """
    monkeypatch.setitem(fteproxy.conf.conf,
                        'runtime.fteproxy.handshake.timeout', seconds)
    return seconds


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
        self.closed = False

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

    def close(self):
        self.closed = True


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


class Clock:
    """A monotonic clock a test drives by hand."""

    START = 1000.0

    def __init__(self):
        self.now = self.START

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class TimeSkippingSocket(FakeSocket):
    """A silent peer on a hand-driven clock.

    Like :class:`SilentSocket`, but each read that would block moves the clock
    forward by its timeout instead of sleeping, so a test can walk past the
    handshake deadline and the discard deadline after it in no time at all.
    """

    def __init__(self, clock, chunks=()):
        super().__init__(chunks)
        self._clock = clock

    def recv(self, _bufsize):
        if self._chunks:
            return self._chunks.pop(0)
        self._clock.advance(self.timeout if self.timeout else 0.1)
        raise socket.timeout()


class CountingCipher:
    """A cipher that records every ``decrypt`` call against its format name."""

    def __init__(self, inner, name, counts):
        self._inner = inner
        self._name = name
        self._counts = counts

    def __getattr__(self, attribute):
        return getattr(self._inner, attribute)

    def decrypt(self, data):
        self._counts[self._name] += 1
        return self._inner.decrypt(data)


class TestDefinitionsReleaseIsolation:

    def test_explicit_release_drives_the_whole_session(self, monkeypatch):
        """The advertised release and every cipher lookup use one catalog.

        ``manual-http`` exists only in 20260110, while the process default in
        this test is 20260903. Before the catalog was captured by the wrapper,
        the hello advertised 20260110 but session setup looked in 20260903 and
        failed before either side could complete the handshake.
        """
        monkeypatch.setitem(fteproxy.conf.conf, 'fteproxy.defs.release',
                            '20260903')
        left, right = socket.socketpair()
        server = fteproxy.wrap_socket(
            left, server_key=SERVER_PRIVATE, defs=SHAPE_CATALOG)
        client = fteproxy.wrap_socket(
            right, server_id=SERVER_PUBLIC, format=FORMAT, mode=MODE,
            defs=SHAPE_CATALOG)
        failures = []

        def run_server():
            try:
                server.handshake()
            except Exception as error:
                failures.append(error)

        thread = threading.Thread(target=run_server)
        thread.start()
        try:
            client.handshake()
            thread.join(timeout=5)
            assert not thread.is_alive()
            assert failures == []
            assert client.negotiated_format == FORMAT
            assert server.negotiated_format == FORMAT

            client.sendall(b'catalog-isolated')
            assert server.recv(16) == b'catalog-isolated'
        finally:
            client.close()
            server.close()
            thread.join(timeout=5)


class TestServerHandshakeEOF:
    """Peer closure before a valid hello produces EOF without an idle polling loop."""

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
        return _client_driver(**overrides)

    def _seal(self, hello_bytes, cover_key):
        return _seal_hello(hello_bytes, cover_key)

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
        """The server reads and discards until its rejection deadline without replying."""
        monkeypatch.setattr(fteproxy.handshake, 'reject_delay', lambda: 0.25)
        # The wait spans the handshake timeout as well, so shorten that too
        # rather than spending the default five seconds here.
        _short_handshake_timeout(monkeypatch, 0.1)
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
    """Pre-1.0 shared-key negotiation is unsupported and receives no reply."""

    LEGACY_KEY = b'\xFF' * 16 + b'\x00' * 16
    LEGACY_CELL = b'\x00' * 32 + SHAPE_CATALOG.encode() + b'manual-http'

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
        monkeypatch.setattr(fteproxy, '_last_matched_format',
                            'manual-http-request')

        fake = FakeSocket([self._sealed('manual-http', 'twin')])
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        server._definitions = definitions
        server.handshake()
        assert server.negotiated_format == 'twin'
        assert fake.sent, 'the server answered'


class TestRejectDeadlineIsAnchoredToTheAccept:
    """Early and timeout-detected rejection use the same deadline origin.

    Otherwise a replayed hello and undecodable bytes occupy distinct close-time
    ranges. This checks deadline construction, not universal probing resistance.
    """

    def test_the_deadline_does_not_move_with_the_detection(self, monkeypatch):
        """Detected at t=0 and detected at t=timeout give the same deadline."""
        monkeypatch.setattr(fteproxy.handshake, 'reject_delay', lambda: 2.0)
        timeout = _short_handshake_timeout(monkeypatch, 5)
        clock = Clock()
        monkeypatch.setattr(time, 'monotonic', clock)

        # Detected at once: this unseals here, but names a stale epoch.
        immediate = FakeSocket([_sealed_hello(epoch=0)])
        early = fteproxy.wrap_socket(immediate, server_key=SERVER_PRIVATE)
        assert early.recv(65536) == b''
        assert immediate.sent == b''

        # Detected only at the deadline: bytes that never unseal, from a peer
        # that stays connected rather than hanging up.
        clock.now = Clock.START
        silent = TimeSkippingSocket(clock, [b'not a client hello'])
        late = fteproxy.wrap_socket(silent, server_key=SERVER_PRIVATE)
        assert late.recv(65536) == b''
        assert silent.sent == b''

        assert late._reject_deadline == early._reject_deadline
        assert early._reject_deadline == Clock.START + timeout + 2.0

    def test_the_pre_handshake_cap_uses_the_same_anchor(self, monkeypatch):
        """The other way a rejection is decided early: too many bytes with no
        hello in them."""
        monkeypatch.setattr(fteproxy.handshake, 'reject_delay', lambda: 2.0)
        timeout = _short_handshake_timeout(monkeypatch, 5)
        clock = Clock()
        monkeypatch.setattr(time, 'monotonic', clock)

        cap = fteproxy._FTESocketWrapper._MAX_PRE_HANDSHAKE_BYTES
        fake = FakeSocket([b'\x00' * (cap + 1)])
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        assert server.recv(65536) == b''
        assert fake.sent == b''
        assert server._reject_deadline == Clock.START + timeout + 2.0

    def test_a_completed_handshake_sets_no_deadline(self, monkeypatch):
        clock = Clock()
        monkeypatch.setattr(time, 'monotonic', clock)
        fake = FakeSocket([_sealed_hello()])
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        server.handshake()
        assert server.handshake_complete
        assert server._reject_deadline is None


def _warm_the_scan():
    """Build every cover cipher the server's first-record scan may use.

    The first use of a format compiles its DFA; a timing test must measure the
    reject deadline, not that.
    """
    cover = fteproxy.handshake.cover_key(SERVER_PUBLIC)
    for name in fteproxy.defs.load_definitions():
        fteproxy._cipher_for(name, cover, cover=True)


class _LoopbackServer:
    """One fteproxy server on 127.0.0.1, serving connections one at a time.

    It answers a handshake it will not accept exactly as ``fteproxy.relay``
    does: ``reject_and_close()``, which reads and discards until the deadline
    and only then closes.
    """

    def __init__(self):
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(('127.0.0.1', 0))
        self._listener.listen(8)
        self.address = self._listener.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                conn, _addr = self._listener.accept()
            except OSError:
                return
            tunnel = fteproxy.wrap_socket(conn, server_key=SERVER_PRIVATE)
            try:
                tunnel.handshake()
            except fteproxy.HandshakeFailedException:
                tunnel.reject_and_close()
                continue
            except (fteproxy._PeerClosed, OSError):
                conn.close()
                continue
            tunnel.close()

    def close(self):
        self._listener.close()
        self._thread.join(timeout=5)


def _seconds_until_close(address, payload):
    """Send ``payload`` and time how long the server holds the connection."""
    sock = socket.create_connection(address, timeout=30)
    try:
        started = time.monotonic()
        sock.sendall(payload)
        while sock.recv(65536):
            pass
        return time.monotonic() - started
    finally:
        sock.close()


class TestRejectTimingOverLoopback:
    """The same property as above, measured on a real socket end to end."""

    def test_a_replay_and_garbage_close_in_the_same_window(self, monkeypatch):
        timeout = _short_handshake_timeout(monkeypatch, 0.2)
        # A real delay is random; two values, dealt out in the same order to
        # both cases, keep the assertion deterministic while still moving.
        delays = itertools.cycle([0.10, 0.20])
        monkeypatch.setattr(fteproxy.handshake, 'reject_delay',
                            lambda: next(delays))
        _warm_the_scan()

        sealed = _sealed_hello()
        server = _LoopbackServer()
        try:
            # Accepted, so the same bytes are a replay from here on.
            _seconds_until_close(server.address, sealed)
            replayed = [_seconds_until_close(server.address, sealed)
                        for _ in range(2)]
            garbage = [_seconds_until_close(server.address, os.urandom(512))
                       for _ in range(2)]
        finally:
            server.close()

        for elapsed in replayed + garbage:
            assert timeout + 0.10 - 0.05 <= elapsed <= timeout + 0.20 + 0.9, (
                'closed %.3fs in, outside the window every rejection shares'
                % elapsed)
        # Overlapping ranges, which is the point: before the fix a replay
        # closed at about the delay and garbage at the timeout plus the delay,
        # with nothing in between.
        assert max(replayed) >= min(garbage)
        assert max(garbage) >= min(replayed)


class TestFirstRecordScanIsBounded:
    """Try each eligible request candidate once even when input arrives in fragments."""

    def _request_names(self):
        return [name for name in fteproxy.defs.load_definitions()
                if name.endswith('-request')]

    def _count_decrypts(self, monkeypatch):
        counts = collections.Counter()
        real = fteproxy._cipher_for

        def counting(format_name, key, cover=False, definitions=None):
            return CountingCipher(real(
                format_name, key, cover=cover, definitions=definitions),
                                  format_name, counts)

        monkeypatch.setattr(fteproxy, '_cipher_for', counting)
        return counts

    def test_each_candidate_is_decrypted_at_most_once(self, monkeypatch):
        names = self._request_names()
        longest = max(fteproxy.defs.getLength(name) for name in names)
        counts = self._count_decrypts(monkeypatch)

        garbage = os.urandom(longest + 8)
        fake = FakeSocket([garbage[i:i + 1] for i in range(len(garbage))])
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        assert server.recv(65536) == b''
        assert fake.sent == b''

        assert counts, 'the scan ran at all'
        assert max(counts.values()) == 1, dict(counts)
        # Every candidate the bytes were long enough for was still tried.
        assert set(counts) == set(names)

    def test_a_fragmented_hello_still_handshakes(self):
        """Remembering a failure must not cost a client whose hello arrives in
        pieces, which is what a small MTU or a slow link gives."""
        sealed = _sealed_hello()
        fake = FakeSocket([sealed[i:i + 1] for i in range(len(sealed))])
        server = fteproxy.wrap_socket(fake, server_key=SERVER_PRIVATE)
        server.handshake()
        assert server.negotiated_format == FORMAT
        assert server.negotiated_mode == MODE
        assert fake.sent, 'the server answered'


class TestControlQueueIsBounded:
    """Unread authenticated control records cannot grow the queue indefinitely."""

    def _peer(self):
        keys = _session_keys()
        return keys, _completed(FakeSocket(), keys, is_client=False)

    def test_a_flood_breaks_the_connection(self, caplog):
        import logging

        keys, peer = self._peer()
        cap = fteproxy._FTESocketWrapper._MAX_CONTROL_RECORDS
        wire = b''.join(
            peer._encoder.encode(fteproxy.record_layer.OPEN, b'dest')
            for _ in range(cap + 1))
        fake = FakeSocket([wire], spin_cap=10)
        wrapper = _completed(fake, keys, is_client=True)
        with caplog.at_level(logging.WARNING, logger='fteproxy'):
            assert wrapper.recv(65536) == b''
        assert wrapper._broken
        assert len(wrapper._control) <= cap
        assert wrapper.pending_eof()
        assert any('control records' in record.message
                   for record in caplog.records), 'the drop was not silent'

    def test_an_ordinary_exchange_is_unaffected(self):
        keys, peer = self._peer()
        wire = (peer._encoder.encode(fteproxy.record_layer.OPEN, b'dest')
                + peer._encoder.encode(fteproxy.record_layer.OPEN_RESULT,
                                       b'\x00'))
        fake = FakeSocket([wire], spin_cap=10)
        wrapper = _completed(fake, keys, is_client=True)
        assert wrapper.recv(65536) == b''
        assert not wrapper._broken
        assert wrapper.next_control_record() == (
            fteproxy.record_layer.OPEN, b'dest')
        assert wrapper.next_control_record() == (
            fteproxy.record_layer.OPEN_RESULT, b'\x00')


class TestClientHandshakeFailure:
    """A client whose handshake fails says so.

    The discard interval is the server's answer to a prober; the client role
    never sets one, so its failure path must not try to wait one out.
    """

    def test_recv_reports_the_failure(self, monkeypatch):
        _short_handshake_timeout(monkeypatch, 0.1)
        fake = SilentSocket()
        client = fteproxy.wrap_socket(fake, server_id=SERVER_PUBLIC,
                                      format=FORMAT, mode=MODE)
        with pytest.raises(fteproxy.HandshakeFailedException):
            client.recv(65536)
        assert client._reject_deadline is None

    def test_handshake_reports_the_same_failure(self, monkeypatch):
        _short_handshake_timeout(monkeypatch, 0.1)
        client = fteproxy.wrap_socket(SilentSocket(), server_id=SERVER_PUBLIC,
                                      format=FORMAT, mode=MODE)
        with pytest.raises(fteproxy.HandshakeTimeoutException):
            client.handshake()

    def test_reject_and_close_is_safe_on_a_client(self, monkeypatch):
        _short_handshake_timeout(monkeypatch, 0.1)
        client = fteproxy.wrap_socket(SilentSocket(), server_id=SERVER_PUBLIC,
                                      format=FORMAT, mode=MODE)
        with pytest.raises(fteproxy.HandshakeFailedException):
            client.handshake()
        fake = client._socket
        client.reject_and_close()
        assert fake.closed, 'the socket was closed, not waited on'


class TestControlRecordSizeIsBounded:
    """Bound control payload bytes as well as the number of queued records.

    OPEN needs at most 259 bytes and OPEN_RESULT one; hybrid bodies can be much larger.
    """

    def _peer(self):
        keys = _session_keys()
        return keys, _completed(FakeSocket(), keys, is_client=False)

    def test_an_oversize_control_record_breaks_the_connection(self, caplog):
        import logging

        keys, peer = self._peer()
        limit = fteproxy._FTESocketWrapper._MAX_CONTROL_BYTES
        wire = peer._encoder.encode(fteproxy.record_layer.OPEN,
                                    b'x' * (limit + 1))
        fake = FakeSocket([wire], spin_cap=10)
        wrapper = _completed(fake, keys, is_client=True)
        with caplog.at_level(logging.WARNING, logger='fteproxy'):
            assert wrapper.recv(65536) == b''
        assert wrapper._broken
        assert not wrapper._control
        assert wrapper.pending_eof()
        assert any('control record' in record.message
                   for record in caplog.records), 'the drop was not silent'

    def test_the_largest_legitimate_open_is_accepted(self):
        import fteproxy.stream

        keys, peer = self._peer()
        # Longest DNS presentation name without a trailing root dot: four
        # legal labels and three separators, 253 bytes total.
        host = '.'.join(('a' * 63, 'b' * 63, 'c' * 63, 'd' * 61))
        payload = fteproxy.stream.encode_open(host, 443)
        assert len(payload) <= fteproxy._FTESocketWrapper._MAX_CONTROL_BYTES
        wire = peer._encoder.encode(fteproxy.record_layer.OPEN, payload)
        fake = FakeSocket([wire], spin_cap=10)
        wrapper = _completed(fake, keys, is_client=True)
        assert wrapper.recv(65536) == b''
        assert not wrapper._broken
        assert wrapper.next_control_record() == (
            fteproxy.record_layer.OPEN, payload)
