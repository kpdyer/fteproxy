#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RFC 1928 conformance for the client listener's SOCKS5 server side.

These drive :mod:`fteproxy.socks` over a socket pair, so they exercise the
byte-level exchange without a tunnel. ``test_relay.py`` covers the same
requests end to end.
"""

import socket
import threading

import pytest

import fteproxy.socks as socks
import fteproxy.stream as stream


@pytest.fixture
def pair():
    """A connected pair: (client end, server end)."""
    client, server = socket.socketpair()
    client.settimeout(5)
    server.settimeout(5)
    yield client, server
    client.close()
    server.close()


def run_handshake(server):
    """Run socks.handshake on a thread; return a dict filled in when it ends."""
    outcome = {}

    def go():
        try:
            outcome['destination'] = socks.handshake(server)
        except socks.SocksError as e:
            outcome['error'] = e

    thread = threading.Thread(target=go, daemon=True)
    thread.start()
    return outcome, thread


def greet(client, methods=(socks.NO_AUTHENTICATION,)):
    client.sendall(bytes((socks.VERSION, len(methods))) + bytes(methods))
    return client.recv(2)


def read_reply(client):
    head = client.recv(4)
    atyp = head[3]
    if atyp == stream.ATYP_IPV4:
        client.recv(4 + 2)
    elif atyp == stream.ATYP_IPV6:
        client.recv(16 + 2)
    else:
        client.recv(client.recv(1)[0] + 2)
    return head


class TestMethodNegotiation:

    def test_no_authentication_is_chosen(self, pair):
        client, server = pair
        outcome, thread = run_handshake(server)
        assert greet(client) == bytes((socks.VERSION, socks.NO_AUTHENTICATION))
        client.sendall(bytes((socks.VERSION, socks.CMD_CONNECT, 0))
                       + stream.encode_address('192.0.2.1', 443))
        thread.join(5)
        assert outcome['destination'] == ('192.0.2.1', 443)

    def test_no_acceptable_method(self, pair):
        client, server = pair
        outcome, thread = run_handshake(server)
        assert greet(client, methods=(0x02,)) == \
            bytes((socks.VERSION, socks.NO_ACCEPTABLE_METHODS))
        thread.join(5)
        assert isinstance(outcome['error'], socks.SocksError)

    def test_a_non_socks5_version_is_refused(self, pair):
        client, server = pair
        outcome, thread = run_handshake(server)
        client.sendall(bytes((0x04, 1, 0)))
        thread.join(5)
        assert 'SOCKS5' in str(outcome['error'])
        # No reply code, so nothing is sent back: a peer that is not speaking
        # SOCKS5 has no reply format to read one in.
        assert outcome['error'].reply is None

    def test_a_client_that_hangs_up_is_reported(self, pair):
        client, server = pair
        outcome, thread = run_handshake(server)
        client.close()
        thread.join(5)
        assert isinstance(outcome['error'], socks.SocksError)


class TestRequest:

    def connect_request(self, client, payload):
        greet(client)
        client.sendall(payload)

    @pytest.mark.parametrize('host,port', [
        ('192.0.2.1', 443),
        ('2001:db8::1', 8080),
        ('example.com', 80),
    ])
    def test_each_address_type(self, pair, host, port):
        client, server = pair
        outcome, thread = run_handshake(server)
        self.connect_request(
            client, bytes((socks.VERSION, socks.CMD_CONNECT, 0))
            + stream.encode_address(host, port))
        thread.join(5)
        assert outcome['destination'] == (host, port)

    @pytest.mark.parametrize('command', [socks.CMD_BIND,
                                         socks.CMD_UDP_ASSOCIATE, 0x09])
    def test_unsupported_commands_get_the_right_reply(self, pair, command):
        client, server = pair
        outcome, thread = run_handshake(server)
        self.connect_request(
            client, bytes((socks.VERSION, command, 0))
            + stream.encode_address('192.0.2.1', 443))
        head = read_reply(client)
        thread.join(5)
        assert head[1] == stream.COMMAND_NOT_SUPPORTED
        assert outcome['error'].reply == stream.COMMAND_NOT_SUPPORTED

    def test_unknown_address_type_gets_the_right_reply(self, pair):
        client, server = pair
        outcome, thread = run_handshake(server)
        self.connect_request(
            client, bytes((socks.VERSION, socks.CMD_CONNECT, 0, 0x09)))
        head = read_reply(client)
        thread.join(5)
        assert head[1] == stream.ADDRESS_TYPE_NOT_SUPPORTED

    def test_a_non_zero_reserved_byte_is_refused(self, pair):
        client, server = pair
        outcome, thread = run_handshake(server)
        self.connect_request(
            client, bytes((socks.VERSION, socks.CMD_CONNECT, 0x01))
            + stream.encode_address('192.0.2.1', 443))
        head = read_reply(client)
        thread.join(5)
        assert head[1] == stream.GENERAL_FAILURE

    def test_a_request_split_across_reads_is_reassembled(self, pair):
        client, server = pair
        outcome, thread = run_handshake(server)
        payload = (bytes((socks.VERSION, socks.CMD_CONNECT, 0))
                   + stream.encode_address('example.com', 443))
        greet(client)
        for index in range(len(payload)):
            client.sendall(payload[index:index + 1])
        thread.join(5)
        assert outcome['destination'] == ('example.com', 443)


class TestReply:

    def test_reply_shape(self, pair):
        client, server = pair
        socks.send_reply(server, stream.SUCCEEDED)
        head = client.recv(4)
        assert head[0] == socks.VERSION
        assert head[1] == stream.SUCCEEDED
        assert head[2] == socks.RESERVED
        assert head[3] == stream.ATYP_IPV4
        assert client.recv(6) == b'\x00\x00\x00\x00\x00\x00'

    def test_a_status_is_passed_through(self, pair):
        client, server = pair
        socks.send_reply(server, stream.CONNECTION_REFUSED)
        assert client.recv(4)[1] == stream.CONNECTION_REFUSED
