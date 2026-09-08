"""Integration tests for the experimental permutation socket negotiation.

These tests deliberately use real sockets and the public ``wrap_socket`` API.
The bootstrap and record codec tests live separately; this module exercises
the connection state machine, including lazy handshakes and failure cleanup.
"""

from __future__ import annotations

import socket
import threading

import pytest

import fteproxy


KEY = bytes(range(32))
UP_PATTERN = r"^[a-z]+$"
DOWN_PATTERN = r"^[A-Z]+$"
UP_LENGTH = 256
DOWN_LENGTH = 312
MODES = ("format", "hybrid")


def _pair(mode=None, *, key=KEY, server_mode=None):
    """Return a connected client/server wrapper pair."""
    client_raw, server_raw = socket.socketpair()
    client_kwargs = {
        "negotiation": "permutation",
        "key": key,
        "outgoing_regex": UP_PATTERN,
        "outgoing_length": UP_LENGTH,
        "incoming_regex": DOWN_PATTERN,
        "incoming_length": DOWN_LENGTH,
    }
    if mode is not None:
        client_kwargs["record_layer_mode"] = mode
    client = fteproxy.wrap_socket(client_raw, **client_kwargs)
    server_kwargs = {
        "negotiation": "permutation",
        "key": key,
    }
    if server_mode is not None:
        server_kwargs["record_layer_mode"] = server_mode
    server = fteproxy.wrap_socket(server_raw, **server_kwargs)
    client.settimeout(8)
    server.settimeout(8)
    return client, server


class _RecordingSocket:
    """Record bytes sent by a wrapper while delegating to a real socket."""

    def __init__(self, raw):
        self.raw = raw
        self.sent = bytearray()

    def sendall(self, data):
        self.sent.extend(data)
        return self.raw.sendall(data)

    def send(self, data):
        count = self.raw.send(data)
        self.sent.extend(data[:count])
        return count

    def __getattr__(self, name):
        return getattr(self.raw, name)


class _MutatingSocket(_RecordingSocket):
    """Mutate or truncate the first application write after handshake."""

    def __init__(self, raw, action, target_write=2, shutdown_after=False):
        super().__init__(raw)
        self._write_count = 0
        self._action = action
        self._target_write = target_write
        self._shutdown_after = shutdown_after

    def sendall(self, data):
        write_number = self._write_count
        self._write_count += 1
        if write_number != self._target_write:
            return super().sendall(data)
        changed = self._action(bytes(data))
        self.sent.extend(changed)
        result = self.raw.sendall(changed)
        if self._shutdown_after:
            self.raw.shutdown(socket.SHUT_WR)
        return result


def _recorded_pair(mode=None, *, client_socket_factory=_RecordingSocket):
    client_raw, server_raw = socket.socketpair()
    client_wire = client_socket_factory(client_raw)
    server_wire = _RecordingSocket(server_raw)
    client_kwargs = {
        "negotiation": "permutation",
        "key": KEY,
        "outgoing_regex": UP_PATTERN,
        "outgoing_length": UP_LENGTH,
        "incoming_regex": DOWN_PATTERN,
        "incoming_length": DOWN_LENGTH,
    }
    if mode is not None:
        client_kwargs["record_layer_mode"] = mode
    client = fteproxy.wrap_socket(client_wire, **client_kwargs)
    server = fteproxy.wrap_socket(
        server_wire, negotiation="permutation", key=KEY
    )
    client.settimeout(8)
    server.settimeout(8)
    return client, server, client_wire, server_wire


def _raw_recv_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise AssertionError("peer closed while capturing a transcript")
        result.extend(chunk)
    return bytes(result)


def _captured_transcript(mode="format"):
    """Return one valid client wire transcript and its server acknowledgement."""
    client, server, client_wire, server_wire = _recorded_pair(mode)
    payload = b"captured application data"
    try:
        _assert_handshake_ok(client, server)
        client.sendall(payload)
        assert server.recv(len(payload)) == payload
        bootstrap_size = 320 * UP_LENGTH
        return (
            bytes(client_wire.sent[:bootstrap_size]),
            bytes(client_wire.sent[bootstrap_size:bootstrap_size + UP_LENGTH]),
            bytes(client_wire.sent[bootstrap_size + UP_LENGTH:]),
            bytes(server_wire.sent),
        )
    finally:
        _close(client, server)


def _close(*sockets):
    for sock in sockets:
        try:
            sock.close()
        except OSError:
            pass


def _run_threads(*jobs, timeout=12):
    """Run ``(callable, result_dict)`` jobs and fail on leaked workers."""
    threads = [threading.Thread(target=job, daemon=True) for job, _ in jobs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout)
    assert all(not thread.is_alive() for thread in threads), "worker hung"
    return [result for _, result in jobs]


def _explicit_handshake(client, server):
    client_result = {}
    server_result = {}

    def client_job():
        try:
            client.do_handshake()
            client_result["ok"] = True
        except BaseException as exc:  # report the worker failure to pytest
            client_result["error"] = exc

    def server_job():
        try:
            server.do_handshake()
            server_result["ok"] = True
        except BaseException as exc:
            server_result["error"] = exc

    _run_threads((client_job, client_result), (server_job, server_result))
    return client_result, server_result


def _assert_handshake_ok(client, server):
    client_result, server_result = _explicit_handshake(client, server)
    assert client_result.get("error") is None, client_result
    assert server_result.get("error") is None, server_result


def _recv_exact(sock, size, recv_size=65536):
    chunks = []
    while sum(map(len, chunks)) < size:
        chunk = sock.recv(min(recv_size, size - sum(map(len, chunks))))
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


@pytest.mark.parametrize("mode", MODES)
def test_explicit_handshake_and_bulk_roundtrip(mode):
    client, server = _pair(mode)
    payload = (b"permutation roundtrip " * 1024) + b"!"
    received = {}

    try:
        _assert_handshake_ok(client, server)

        server_result = {}

        def server_job():
            try:
                received["data"] = _recv_exact(server, len(payload))
                server.sendall(received["data"])
            except BaseException as exc:
                server_result["error"] = exc

        result = {}

        def client_job():
            try:
                client.sendall(payload)
                result["echo"] = _recv_exact(client, len(payload))
            except BaseException as exc:
                result["error"] = exc

        _run_threads((server_job, server_result), (client_job, result))
        assert server_result.get("error") is None, server_result
        assert result.get("error") is None, result
        assert received["data"] == payload
        assert result["echo"] == payload
    finally:
        _close(client, server)


def test_listener_accept_and_connect_use_permutation_negotiation():
    listener_raw = socket.socket()
    listener = fteproxy.wrap_socket(listener_raw, negotiation="permutation", key=KEY)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    address = listener.getsockname()
    payload = b"listener path"
    result = {}

    def server_job():
        try:
            conn, _ = listener.accept()
            conn.settimeout(8)
            result["data"] = conn.recv(len(payload))
            conn.sendall(b"reply")
            conn.close()
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=server_job, daemon=True)
    thread.start()
    client_raw = socket.socket()
    client = fteproxy.wrap_socket(
        client_raw,
        negotiation="permutation",
        key=KEY,
        outgoing_regex=UP_PATTERN,
        outgoing_length=UP_LENGTH,
        incoming_regex=DOWN_PATTERN,
        incoming_length=DOWN_LENGTH,
    )
    try:
        client.settimeout(8)
        client.connect(address)
        client.sendall(payload)
        assert client.recv(6) == b"reply"
        thread.join(12)
        assert not thread.is_alive()
        assert result.get("error") is None, result
        assert result.get("data") == payload
    finally:
        _close(client, listener)


def test_lazy_handshake_send_first():
    client, server = _pair()
    payload = b"send triggers the handshake"
    result = {}

    def server_job():
        try:
            result["data"] = server.recv(len(payload))
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=server_job, daemon=True)
    thread.start()
    try:
        client.sendall(payload)
        thread.join(12)
        assert not thread.is_alive()
        assert result.get("error") is None, result
        assert result["data"] == payload
    finally:
        _close(client, server)


def test_lazy_handshake_recv_first_with_server_greeting():
    client, server = _pair()
    greeting = b"server greeting"
    result = {}

    def server_job():
        try:
            server.sendall(greeting)
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=server_job, daemon=True)
    thread.start()
    try:
        assert client.recv(len(greeting)) == greeting
        thread.join(12)
        assert not thread.is_alive()
        assert result.get("error") is None, result
    finally:
        _close(client, server)


def test_small_recvsize_preserves_buffered_application_data():
    client, server = _pair()
    payload = b"buffer preservation" * 32
    result = {}

    def client_job():
        try:
            client.sendall(payload)
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=client_job, daemon=True)
    thread.start()
    try:
        chunks = []
        while sum(map(len, chunks)) < len(payload):
            chunks.append(server.recv(1))
        thread.join(12)
        assert not thread.is_alive()
        assert result.get("error") is None, result
        assert b"".join(chunks) == payload
    finally:
        _close(client, server)


def test_server_does_not_load_global_definitions(monkeypatch):
    # The negotiated patterns come from the authenticated bootstrap.  A server
    # must not consult the local definitions release while accepting a client.
    import fteproxy.defs

    def unexpected_load():
        pytest.fail("permutation server loaded local definitions")

    monkeypatch.setattr(fteproxy.defs, "load_definitions", unexpected_load)
    client, server = _pair()
    try:
        _assert_handshake_ok(client, server)
        client.sendall(b"definitions are not required")
        assert server.recv(1024) == b"definitions are not required"
    finally:
        _close(client, server)


def test_truncated_bootstrap_fails_closed_at_server():
    client_raw, server_raw = socket.socketpair()
    server = fteproxy.wrap_socket(server_raw, negotiation="permutation", key=KEY)
    server.settimeout(3)
    try:
        client_raw.sendall(b"partial bootstrap")
        client_raw.shutdown(socket.SHUT_WR)
        with pytest.raises(ConnectionError):
            server.do_handshake()
    finally:
        _close(client_raw, server)


def test_truncated_bootstrap_fails_closed_at_client():
    client_raw, peer = socket.socketpair()
    client = fteproxy.wrap_socket(
        client_raw,
        negotiation="permutation",
        key=KEY,
        outgoing_regex=UP_PATTERN,
        outgoing_length=UP_LENGTH,
        incoming_regex=DOWN_PATTERN,
        incoming_length=DOWN_LENGTH,
    )
    client.settimeout(3)
    try:
        # The raw peer receives enough bytes to prove this is a partial
        # handshake, then closes before sending an acknowledgement.
        client_job = {}

        def start_handshake():
            try:
                client.do_handshake()
            except BaseException as exc:
                client_job["error"] = exc

        thread = threading.Thread(target=start_handshake, daemon=True)
        thread.start()
        assert peer.recv(512)
        peer.close()
        thread.join(12)
        assert not thread.is_alive()
        assert isinstance(client_job.get("error"), ConnectionError)
    finally:
        _close(client, peer)


def test_timeout_fails_closed_without_peer_data():
    client_raw, peer = socket.socketpair()
    client = fteproxy.wrap_socket(
        client_raw,
        negotiation="permutation",
        key=KEY,
        outgoing_regex=UP_PATTERN,
        outgoing_length=UP_LENGTH,
        incoming_regex=DOWN_PATTERN,
        incoming_length=DOWN_LENGTH,
    )
    client.settimeout(0.2)
    try:
        with pytest.raises(socket.timeout):
            client.do_handshake()
    finally:
        _close(client, peer)


def test_key_mismatch_does_not_release_application_data():
    client_raw, server_raw = socket.socketpair()
    client = fteproxy.wrap_socket(
        client_raw,
        negotiation="permutation",
        key=KEY,
        outgoing_regex=UP_PATTERN,
        outgoing_length=UP_LENGTH,
        incoming_regex=DOWN_PATTERN,
        incoming_length=DOWN_LENGTH,
    )
    server = fteproxy.wrap_socket(
        server_raw, negotiation="permutation", key=bytes(reversed(range(32)))
    )
    client.settimeout(3)
    server.settimeout(3)
    client_result, server_result = _explicit_handshake(client, server)
    try:
        expected = (ConnectionError, socket.timeout)
        assert isinstance(client_result.get("error"), expected)
        assert isinstance(server_result.get("error"), expected)
        assert "ok" not in client_result
        assert "ok" not in server_result
        assert client.fileno() == -1
        assert server.fileno() == -1
    finally:
        _close(client, server)


def test_record_layer_mode_constraint_rejects_mismatch():
    client, server = _pair("hybrid", server_mode="format")
    try:
        client_result, server_result = _explicit_handshake(client, server)
        assert isinstance(client_result.get("error"), ConnectionError)
        assert isinstance(server_result.get("error"), ConnectionError)
        assert "ok" not in client_result
        assert "ok" not in server_result
    finally:
        _close(client, server)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"key": b"short"},
        {"key": bytes(range(33))},
        {"outgoing_regex": None},
        {"incoming_regex": None},
        {"outgoing_regex": "x" * 221},
        {"outgoing_length": 513},
        {"incoming_length": 0},
        {"outgoing_regex": "^[ab]+$", "outgoing_length": 28},
        {"record_layer_mode": "unknown"},
    ],
)
def test_invalid_caller_configuration_raises_value_error(kwargs):
    options = {
        "negotiation": "permutation",
        "key": KEY,
        "outgoing_regex": UP_PATTERN,
        "outgoing_length": UP_LENGTH,
        "incoming_regex": DOWN_PATTERN,
        "incoming_length": DOWN_LENGTH,
    }
    options.update(kwargs)
    raw, peer = socket.socketpair()
    try:
        with pytest.raises(ValueError):
            fteproxy.wrap_socket(raw, **options)
    finally:
        _close(raw, peer)


def test_server_requires_no_client_format_arguments():
    client, server = _pair()
    try:
        _assert_handshake_ok(client, server)
    finally:
        _close(client, server)


def test_concurrent_explicit_handshakes_are_safe():
    client, server = _pair()
    results = [{}, {}, {}, {}]

    def job(endpoint, result):
        def run():
            try:
                endpoint.do_handshake()
                result['ok'] = True
            except BaseException as exc:
                result['error'] = exc
        return run

    try:
        # Competing calls on each endpoint must emit only one handshake.
        _run_threads(*[(job(endpoint, result), result) for endpoint, result in
                       zip((client, client, server, server), results)])
        assert all(result.get('ok') for result in results), results
        client.sendall(b'one negotiated stream')
        assert server.recv(32) == b'one negotiated stream'
    finally:
        _close(client, server)


def test_captured_bootstrap_final_and_data_cannot_unlock_fresh_server():
    captured_bootstrap, captured_final, captured_data, _ = _captured_transcript()
    raw_peer, server_raw = socket.socketpair()
    server = fteproxy.wrap_socket(server_raw, negotiation="permutation", key=KEY)
    server.settimeout(5)
    result = {}

    def server_job():
        try:
            server.do_handshake()
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=server_job, daemon=True)
    thread.start()
    try:
        raw_peer.sendall(captured_bootstrap)
        # Let the fresh server issue a fresh challenge before replaying the
        # old confirmation and application record.
        _raw_recv_exact(raw_peer, DOWN_LENGTH)
        raw_peer.sendall(captured_final + captured_data)
        thread.join(12)
        assert not thread.is_alive()
        assert isinstance(result.get("error"), ConnectionError)
    finally:
        _close(raw_peer, server)


def test_server_never_compiles_authenticated_patterns_before_bootstrap_tag(monkeypatch):
    import fteproxy.permutation as permutation

    calls = []
    original_compile = permutation._compile

    def record_compile(parameters, key):
        calls.append(parameters)
        return original_compile(parameters, key)

    monkeypatch.setattr(permutation, "_compile", record_compile)
    raw_peer, server_raw = socket.socketpair()
    server = fteproxy.wrap_socket(server_raw, negotiation="permutation", key=KEY)
    server.settimeout(5)
    result = {}

    def server_job():
        try:
            server.do_handshake()
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=server_job, daemon=True)
    thread.start()
    try:
        # This fills the largest candidate width's first 320 words with a
        # deliberately unauthenticated, but otherwise cheap, repeated symbol.
        raw_peer.sendall(b"x" * (320 * UP_LENGTH))
        raw_peer.shutdown(socket.SHUT_WR)
        thread.join(12)
        assert not thread.is_alive()
        assert isinstance(result.get("error"), ConnectionError)
        assert calls == []
    finally:
        _close(raw_peer, server)


def test_tampered_server_acknowledgement_is_rejected(monkeypatch):
    captured_bootstrap, _, _, captured_ack = _captured_transcript()
    import fteproxy.permutation as permutation

    # Force this client attempt to emit the captured bootstrap, so the
    # captured acknowledgement is otherwise valid for its transcript.
    original_encode = permutation.bootstrap.encode
    monkeypatch.setattr(
        permutation.bootstrap,
        "encode",
        lambda key, words, description: captured_bootstrap,
    )
    raw_peer, client_raw = socket.socketpair()
    client = fteproxy.wrap_socket(
        client_raw,
        negotiation="permutation",
        key=KEY,
        outgoing_regex=UP_PATTERN,
        outgoing_length=UP_LENGTH,
        incoming_regex=DOWN_PATTERN,
        incoming_length=DOWN_LENGTH,
    )
    client.settimeout(5)
    result = {}

    def client_job():
        try:
            client.do_handshake()
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=client_job, daemon=True)
    thread.start()
    try:
        assert _raw_recv_exact(raw_peer, len(captured_bootstrap)) == captured_bootstrap
        tampered_ack = bytearray(captured_ack)
        tampered_ack[-1] ^= 1
        raw_peer.sendall(tampered_ack)
        thread.join(12)
        assert not thread.is_alive()
        assert isinstance(result.get("error"), ConnectionError)
    finally:
        monkeypatch.setattr(permutation.bootstrap, "encode", original_encode)
        _close(raw_peer, client)


def test_tampered_client_confirmation_is_rejected():
    def flip_final(data):
        changed = bytearray(data)
        changed[-1] ^= 1
        return bytes(changed)

    client, server, client_wire, server_wire = _recorded_pair(
        client_socket_factory=lambda raw: _MutatingSocket(
            raw, flip_final, target_write=1
        )
    )
    client_result, server_result = _explicit_handshake(client, server)
    try:
        assert isinstance(server_result.get("error"), ConnectionError)
        assert client_result.get("error") is None or isinstance(
            client_result.get("error"), ConnectionError
        )
        assert len(client_wire.sent) >= 320 * UP_LENGTH + UP_LENGTH
        assert len(server_wire.sent) == DOWN_LENGTH
    finally:
        _close(client, server)


@pytest.mark.parametrize("mode", MODES)
def test_tampered_application_record_is_not_released(mode):
    def flip_data(data):
        changed = bytearray(data)
        changed[-1] ^= 1
        return bytes(changed)

    client, server, _, _ = _recorded_pair(
        mode,
        client_socket_factory=lambda raw: _MutatingSocket(
            raw, flip_data, target_write=2, shutdown_after=True
        ),
    )
    payload = b"tampered application record"
    sender_result = {}

    def sender():
        try:
            client.sendall(payload)
        except BaseException as exc:
            sender_result["error"] = exc

    thread = threading.Thread(target=sender, daemon=True)
    thread.start()
    try:
        # The mutation is authenticated as bad data. Closing the write side
        # makes the receiver fail closed rather than waiting for repair bytes.
        with pytest.raises(ConnectionError):
            server.recv(len(payload))
        thread.join(12)
        assert not thread.is_alive()
        assert sender_result.get("error") is None, sender_result
    finally:
        _close(client, server)


@pytest.mark.parametrize("mode", MODES)
def test_truncated_final_application_record_raises_connection_error(mode):
    def truncate_data(data):
        return data[:-1]

    client, server, _, _ = _recorded_pair(
        mode,
        client_socket_factory=lambda raw: _MutatingSocket(
            raw, truncate_data, target_write=2, shutdown_after=True
        ),
    )
    payload = b"truncated final application record"
    sender_result = {}

    def sender():
        try:
            client.sendall(payload)
        except BaseException as exc:
            sender_result["error"] = exc

    thread = threading.Thread(target=sender, daemon=True)
    thread.start()
    try:
        # The adapter closes the stream after dropping the last wire byte.
        with pytest.raises(ConnectionError):
            server.recv(len(payload))
        thread.join(12)
        assert not thread.is_alive()
        assert sender_result.get("error") is None, sender_result
    finally:
        _close(client, server)
