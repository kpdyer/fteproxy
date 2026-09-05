#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SOCKS5 CONNECT handling for the client's local -D listener.

Supports no authentication and IPv4, IPv6, or domain destinations. BIND and
UDP ASSOCIATE return COMMAND_NOT_SUPPORTED. Addresses are decoded and then
re-encoded by the tunnel using the same layout as OPEN; OPEN_RESULT uses the
SOCKS5 reply status codes.
"""

import fteproxy.stream


VERSION = 0x05

#: Method identifiers (RFC 1928 section 3).
NO_AUTHENTICATION = 0x00
NO_ACCEPTABLE_METHODS = 0xFF

#: Commands (section 4).
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

RESERVED = 0x00


class SocksError(Exception):
    """A request this listener will not serve.

    ``reply`` is the RFC 1928 reply code to send back, or None when the
    exchange failed before a reply is meaningful (a bad version, or the client
    hanging up).
    """

    def __init__(self, message, reply=None):
        super().__init__(message)
        self.reply = reply


def _read_exactly(sock, count):
    buffer = b''
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            raise SocksError('client closed during the SOCKS handshake')
        buffer += chunk
    return buffer


def negotiate_method(sock):
    """Do the method-selection exchange, choosing "no authentication"."""
    header = _read_exactly(sock, 2)
    if header[0] != VERSION:
        raise SocksError('not a SOCKS5 client (version 0x%02x)' % header[0])
    methods = _read_exactly(sock, header[1]) if header[1] else b''
    if NO_AUTHENTICATION not in methods:
        sock.sendall(bytes((VERSION, NO_ACCEPTABLE_METHODS)))
        raise SocksError('client offered no method this listener supports')
    sock.sendall(bytes((VERSION, NO_AUTHENTICATION)))


def read_request(sock):
    """Read a CONNECT request and return (host, port).

    Raise SocksError on refusal; its reply code is None when no reply is appropriate.
    """
    header = _read_exactly(sock, 4)
    version, command, reserved, atyp = header
    if version != VERSION:
        raise SocksError('request version 0x%02x' % version)
    if reserved != RESERVED:
        raise SocksError('reserved byte is 0x%02x' % reserved,
                         fteproxy.stream.GENERAL_FAILURE)
    if command != CMD_CONNECT:
        raise SocksError('command 0x%02x is not CONNECT' % command,
                         fteproxy.stream.COMMAND_NOT_SUPPORTED)

    if atyp == fteproxy.stream.ATYP_IPV4:
        rest = _read_exactly(sock, 4 + 2)
    elif atyp == fteproxy.stream.ATYP_IPV6:
        rest = _read_exactly(sock, 16 + 2)
    elif atyp == fteproxy.stream.ATYP_DOMAIN:
        length = _read_exactly(sock, 1)
        rest = length + _read_exactly(sock, length[0] + 2)
    else:
        raise SocksError('address type 0x%02x' % atyp,
                         fteproxy.stream.ADDRESS_TYPE_NOT_SUPPORTED)

    try:
        host, port, _end = fteproxy.stream.read_address(bytes((atyp,)) + rest)
    except fteproxy.stream.InvalidAddress as e:
        raise SocksError(str(e), fteproxy.stream.ADDRESS_TYPE_NOT_SUPPORTED)
    return host, port


def send_reply(sock, status, bound=('0.0.0.0', 0)):
    """Send a SOCKS5 reply with status and the supplied bound address.

    The relay defaults to 0.0.0.0:0 because OPEN_RESULT carries only a status.
    RFC 1928 specifies the actual outgoing bound address for CONNECT; this
    placeholder is a limitation of the current relay, not a protocol guarantee.
    """
    host, port = bound
    sock.sendall(bytes((VERSION, status, RESERVED))
                 + fteproxy.stream.encode_address(host, port))


def handshake(sock):
    """Run the whole server side and return the requested ``(host, port)``.

    On a request this listener will not serve, the reply goes out here and
    :class:`SocksError` is raised, so the caller only has to close.
    """
    try:
        negotiate_method(sock)
        return read_request(sock)
    except SocksError as e:
        if e.reply is not None:
            try:
                send_reply(sock, e.reply)
            except OSError:
                pass
        raise
    except OSError as e:
        raise SocksError('SOCKS handshake I/O failed: %s' % e)
