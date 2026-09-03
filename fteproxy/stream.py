#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stream messages and destination policy.

A 1.0 tunnel carries the destination in band: the client sends an
:data:`~fteproxy.record_layer.OPEN` record naming where it wants to go, and the
server answers with an :data:`~fteproxy.record_layer.OPEN_RESULT` carrying a
status. The server therefore needs no forward address of its own, and the
client can offer SOCKS5 or a port forward without either end being
reconfigured.

The address encoding is SOCKS5's (RFC 1928 section 4), so a SOCKS request can
be passed through without being re-encoded, and the status codes are SOCKS5's
reply codes, so the client can map an OPEN_RESULT straight onto its reply.

:class:`AllowRules` is the server's answer to "who may I dial for you". Its
default is the one thing a shared-key tunnel never had: a policy that does not
hand every holder of the connection string a route to the server's own
localhost.
"""

import fnmatch
import ipaddress
import socket


#: SOCKS5 address types (RFC 1928 section 4).
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

#: SOCKS5 reply codes, reused verbatim as OPEN_RESULT statuses.
SUCCEEDED = 0x00
GENERAL_FAILURE = 0x01
NOT_ALLOWED = 0x02
NETWORK_UNREACHABLE = 0x03
HOST_UNREACHABLE = 0x04
CONNECTION_REFUSED = 0x05
TTL_EXPIRED = 0x06
COMMAND_NOT_SUPPORTED = 0x07
ADDRESS_TYPE_NOT_SUPPORTED = 0x08

STATUS_NAMES = {
    SUCCEEDED: 'succeeded',
    GENERAL_FAILURE: 'general failure',
    NOT_ALLOWED: 'not allowed by ruleset',
    NETWORK_UNREACHABLE: 'network unreachable',
    HOST_UNREACHABLE: 'host unreachable',
    CONNECTION_REFUSED: 'connection refused',
    TTL_EXPIRED: 'TTL expired',
    COMMAND_NOT_SUPPORTED: 'command not supported',
    ADDRESS_TYPE_NOT_SUPPORTED: 'address type not supported',
}


def status_name(status):
    return STATUS_NAMES.get(status, 'status 0x%02x' % status)


class InvalidAddress(Exception):
    """An address that cannot be encoded, or a message that cannot be parsed."""


class InvalidRule(Exception):
    """An ``--allow`` rule that cannot be parsed."""


# --------------------------------------------------------------------------- #
# Address encoding
# --------------------------------------------------------------------------- #

def encode_address(host, port):
    """Encode ``(host, port)`` as ``atyp || addr || port``.

    A host that parses as an IP address is sent as one; anything else is sent
    as a name, so the server does the resolving and the client's DNS never
    leaves the tunnel.
    """
    if not 0 <= port <= 0xFFFF:
        raise InvalidAddress('port %r is out of range' % (port,))
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode('idna') if not host.isascii() else host.encode('ascii')
        if not 0 < len(name) <= 0xFF:
            raise InvalidAddress('host name must be 1 to 255 bytes')
        return (bytes((ATYP_DOMAIN, len(name))) + name
                + port.to_bytes(2, 'big'))
    atyp = ATYP_IPV4 if address.version == 4 else ATYP_IPV6
    return bytes((atyp,)) + address.packed + port.to_bytes(2, 'big')


def decode_address(data):
    """Decode ``atyp || addr || port``, which must be the whole of ``data``."""
    host, port, consumed = read_address(data)
    if consumed != len(data):
        raise InvalidAddress('%d trailing bytes after the address'
                             % (len(data) - consumed))
    return host, port


def read_address(data, offset=0):
    """Read one address at ``offset``; return ``(host, port, end offset)``.

    Separate from :func:`decode_address` because a SOCKS5 request has the same
    address at a fixed offset inside a longer message.
    """
    if len(data) - offset < 1:
        raise InvalidAddress('address is empty')
    atyp = data[offset]
    offset += 1
    if atyp == ATYP_IPV4:
        width = 4
    elif atyp == ATYP_IPV6:
        width = 16
    elif atyp == ATYP_DOMAIN:
        if len(data) - offset < 1:
            raise InvalidAddress('truncated domain length')
        width = data[offset]
        offset += 1
        if width == 0:
            raise InvalidAddress('empty domain name')
    else:
        raise InvalidAddress('unknown address type 0x%02x' % atyp)

    if len(data) - offset < width + 2:
        raise InvalidAddress('truncated address')
    raw = data[offset:offset + width]
    offset += width
    port = int.from_bytes(data[offset:offset + 2], 'big')
    offset += 2

    if atyp == ATYP_DOMAIN:
        try:
            host = raw.decode('idna')
        except UnicodeError:
            raise InvalidAddress('domain name is not valid IDNA')
    else:
        host = str(ipaddress.ip_address(raw))
    return host, port, offset


#: OPEN and OPEN_RESULT payloads. The names exist so call sites read as
#: protocol steps rather than as byte twiddling.
encode_open = encode_address
decode_open = decode_address


def encode_open_result(status):
    if not 0 <= status <= 0xFF:
        raise InvalidAddress('status %r is out of range' % (status,))
    return bytes((status,))


def decode_open_result(payload):
    if len(payload) != 1:
        raise InvalidAddress('OPEN_RESULT payload is %d bytes, expected 1'
                             % len(payload))
    return payload[0]


# --------------------------------------------------------------------------- #
# Address classification
# --------------------------------------------------------------------------- #

def is_restricted(address):
    """Whether ``address`` is one the default policy refuses.

    Loopback, link-local (including IPv4's 169.254/16 and its
    RFC 3927 DHCP-failure meaning) and the unspecified address all name
    something on or adjacent to the server host rather than a destination the
    client meant to reach. Handing those to every holder of a connection
    string is how a tunnel becomes a route into an admin interface.

    ``address`` is an ``ipaddress`` object or a string; an IPv4-mapped IPv6
    address is unmapped first, since ``::ffff:127.0.0.1`` reaches the same
    place ``127.0.0.1`` does.
    """
    if not isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        address = ipaddress.ip_address(address)
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return (address.is_loopback or address.is_link_local
            or address.is_unspecified)


# --------------------------------------------------------------------------- #
# Allow rules
# --------------------------------------------------------------------------- #

def _split_host_port(text):
    """``host``, ``host:port``, ``[v6]`` or ``[v6]:port`` -> ``(host, port)``.

    ``port`` is None when the text carries none. IPv6 literals need brackets
    when a port follows, because ``::1:443`` is a valid address on its own.
    """
    text = text.strip()
    if not text:
        raise InvalidRule('empty rule')
    if text.startswith('['):
        end = text.find(']')
        if end < 0:
            raise InvalidRule('unclosed [ in %r' % text)
        host = text[1:end]
        rest = text[end + 1:]
        if not rest:
            return host, None
        if not rest.startswith(':'):
            raise InvalidRule('expected :PORT after ] in %r' % text)
        return host, _port(rest[1:], text)
    if text.count(':') == 1:
        host, _, port = text.partition(':')
        return host, _port(port, text)
    # No colon, or several: a bare name/IPv4, or a bare IPv6 literal.
    return text, None


def _port(text, whole):
    if not text.isdigit():
        raise InvalidRule('port %r in %r is not a number' % (text, whole))
    port = int(text)
    if not 0 < port <= 0xFFFF:
        raise InvalidRule('port %d in %r is out of range' % (port, whole))
    return port


class _Rule:
    """One parsed ``--allow`` rule."""

    def __init__(self, text):
        self.text = text
        self.port = None
        self.network = None
        self.pattern = None
        self.any = (text.strip() == 'any')
        if self.any:
            return
        host, self.port = _split_host_port(text)
        if not host:
            raise InvalidRule('no host in %r' % text)
        if '*' in host or '?' in host:
            self.pattern = host.lower()
            return
        try:
            self.network = ipaddress.ip_network(host, strict=False)
        except ValueError:
            self.pattern = host.lower()

    def matches(self, host, port):
        """Whether this rule permits ``host:port``.

        A request naming an address is matched against address and CIDR rules;
        a request naming a name is matched against name rules. They are
        different questions -- a name rule cannot vouch for wherever that name
        resolves to today -- so neither kind answers the other.
        """
        if self.port is not None and self.port != port:
            return False
        if self.any:
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None:
            if address.version == 6 and address.ipv4_mapped is not None:
                address = address.ipv4_mapped
            return (self.network is not None
                    and address.version == self.network.version
                    and address in self.network)
        return (self.pattern is not None
                and fnmatch.fnmatchcase(host.lower(), self.pattern))


class AllowRules:
    """The destinations a server is willing to dial.

    With no rules the policy is Decision D3: every destination except the
    server's own loopback and link-local addresses, checked both on what the
    client asked for and on what the name resolved to, so a name pointing at
    127.0.0.1 does not walk around it.

    With one or more rules the rules are the policy: only what they name is
    reachable, and the loopback restriction no longer applies to what a rule
    explicitly permits -- ``--allow 127.0.0.1:8081`` is how a local service is
    published. ``--allow any`` restores "everything", loopback included.
    """

    def __init__(self, rules=()):
        self._rules = [_Rule(text) for text in rules]

    @property
    def has_rules(self):
        return bool(self._rules)

    @property
    def rule_text(self):
        return [rule.text for rule in self._rules]

    def describe(self):
        if not self._rules:
            return ('every destination except the loopback and link-local '
                    'addresses of this host')
        return ', '.join(rule.text for rule in self._rules)

    def check(self, host, port):
        """The status for a request naming ``host:port``, before resolution.

        :data:`SUCCEEDED` means "carry on and resolve"; anything else is the
        OPEN_RESULT to send back.
        """
        if self._rules:
            for rule in self._rules:
                if rule.matches(host, port):
                    return SUCCEEDED
            return NOT_ALLOWED
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            # A name: the default policy can only be applied once it resolves.
            return SUCCEEDED
        return NOT_ALLOWED if is_restricted(address) else SUCCEEDED

    def check_resolved(self, host, port, address):
        """The status for one address ``host`` resolved to.

        A rule that named the destination explicitly has already vouched for
        it, so an operator who published ``127.0.0.1:8081`` gets it. Otherwise
        the default policy applies here too, which is what stops
        ``localhost``, a rebinding name, or an AAAA record of ``::1`` from
        reaching a service the policy meant to keep private.
        """
        if self._rules:
            for rule in self._rules:
                if rule.matches(host, port) or rule.matches(str(address), port):
                    return SUCCEEDED
            return NOT_ALLOWED
        return NOT_ALLOWED if is_restricted(address) else SUCCEEDED


# --------------------------------------------------------------------------- #
# Dialling
# --------------------------------------------------------------------------- #

def status_for_error(error):
    """Map a connect() failure onto the SOCKS5 reply code that describes it."""
    if isinstance(error, socket.gaierror):
        return HOST_UNREACHABLE
    if isinstance(error, socket.timeout):
        return TTL_EXPIRED
    errno = getattr(error, 'errno', None)
    import errno as _errno
    if errno in (_errno.ECONNREFUSED,):
        return CONNECTION_REFUSED
    if errno in (_errno.ENETUNREACH, _errno.ENETDOWN):
        return NETWORK_UNREACHABLE
    if errno in (_errno.EHOSTUNREACH, _errno.EHOSTDOWN):
        return HOST_UNREACHABLE
    if errno in (_errno.ETIMEDOUT,):
        return TTL_EXPIRED
    return GENERAL_FAILURE


def connect(host, port, rules, timeout):
    """Resolve and dial ``host:port`` under ``rules``.

    Returns ``(status, socket)``: on anything but :data:`SUCCEEDED` the socket
    is None and the status is what the OPEN_RESULT should carry. Every
    candidate address is checked against the policy, so a name that resolves
    to a restricted address is refused rather than dialled.
    """
    status = rules.check(host, port)
    if status != SUCCEEDED:
        return status, None

    try:
        candidates = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return status_for_error(e), None
    if not candidates:
        return HOST_UNREACHABLE, None

    last = GENERAL_FAILURE
    refused_by_policy = False
    for family, socktype, proto, _canonname, sockaddr in candidates:
        address = ipaddress.ip_address(sockaddr[0])
        if rules.check_resolved(host, port, address) != SUCCEEDED:
            refused_by_policy = True
            continue
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
        except OSError as e:
            sock.close()
            last = status_for_error(e)
            continue
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return SUCCEEDED, sock

    if refused_by_policy and last == GENERAL_FAILURE:
        return NOT_ALLOWED, None
    return last, None
