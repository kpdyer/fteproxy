#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Logical-readiness tests for sockets used by the relay."""

import socket
import select

import fteproxy
import fteproxy.defs
import fteproxy.handshake
import fteproxy.network_io
import fteproxy.record_layer


def _completed_wrapper(sock):
    _private, server_public = fteproxy.generate_server_key()
    wrapped = fteproxy.wrap_socket(sock, server_id=server_public)
    wrapped._handshake_done = True
    return wrapped


def test_decoded_data_bypasses_select():
    """Buffered wrapper DATA is readable even while its fd is idle."""
    local, peer = socket.socketpair()
    try:
        wrapped = _completed_wrapper(local)
        wrapped._incoming_buffer = b'already-decoded'

        alive, data = fteproxy.network_io.recvall_from_socket(
            wrapped, select_timeout=0)

        assert alive
        assert data == b'already-decoded'
    finally:
        local.close()
        peer.close()


def test_logical_eof_bypasses_select():
    local, peer = socket.socketpair()
    try:
        wrapped = _completed_wrapper(local)
        wrapped._peer_closed = True

        alive, data = fteproxy.network_io.recvall_from_socket(
            wrapped, select_timeout=0)

        assert not alive
        assert data == b''
    finally:
        local.close()
        peer.close()


def test_open_result_and_first_data_from_one_read_are_both_delivered():
    """A control wait must not strand DATA decoded from the same wire read."""
    local, remote = socket.socketpair()
    private, public = fteproxy.generate_server_key()
    client = fteproxy.wrap_socket(
        local, server_id=public, format='http', mode='hybrid', defs='20260903')
    server = fteproxy.wrap_socket(remote, server_key=private, defs='20260903')
    definitions = fteproxy.defs.load_definitions('20260903')
    keys = fteproxy.handshake.derive_session_keys(
        transcript=b'\x01' * 32, dh_ee=b'\x02' * 32, dh_es=b'\x03' * 32)
    client._encoder, client._decoder = fteproxy._session_channel(
        'http', 'hybrid', keys, is_client=True, definitions=definitions)
    server._encoder, server._decoder = fteproxy._session_channel(
        'http', 'hybrid', keys, is_client=False, definitions=definitions)
    client._handshake_done = server._handshake_done = True

    try:
        wire = (
            server._encoder.encode(fteproxy.record_layer.OPEN_RESULT, b'\x00')
            + server._encoder.encode(fteproxy.record_layer.DATA, b'first-data')
        )
        remote.sendall(wire)

        assert client._wait_control(
            fteproxy.record_layer.OPEN_RESULT, timeout=1) == b'\x00'
        assert select.select([client], [], [], 0)[0] == []

        alive, data = fteproxy.network_io.recvall_from_socket(
            client, select_timeout=0)
        assert alive
        assert data == b'first-data'
    finally:
        client.close()
        server.close()
