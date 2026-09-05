#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OPEN address encoding, SOCKS5-style results, and destination policy.

The client requests a destination; the server applies AllowRules before and
after resolution, connects to an allowed numeric address, and returns a status.
Addresses use the SOCKS5 wire layout and are decoded/re-encoded at relay edges.
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

def _validate_domain_bytes(name):
    """Reject resolver-ambiguous or non-DNS bytes in a SOCKS domain name."""
    if not 0 < len(name) <= 0xFF:
        raise InvalidAddress('host name must be 1 to 255 bytes')
    if any(byte <= 0x20 or 0x7f <= byte <= 0x9f for byte in name):
        raise InvalidAddress('host name contains whitespace or control bytes')

    body = name[:-1] if name.endswith(b'.') else name
    labels = body.split(b'.')
    if not body or any(not label or len(label) > 63 for label in labels):
        raise InvalidAddress('host name has an empty or overlong DNS label')
    for label in labels:
        if any(not (ord('a') <= byte <= ord('z')
                   or ord('A') <= byte <= ord('Z')
                   or ord('0') <= byte <= ord('9')
                   or byte in (ord('-'), ord('_')))
               for byte in label):
            raise InvalidAddress('host name contains non-DNS characters')


def _encode_domain_name(host):
    """Return one validated IDNA domain without ever quoting it in errors."""
    if not isinstance(host, str):
        raise InvalidAddress('host name must be text')
    if any(char.isspace() or ord(char) < 0x20
           or 0x7f <= ord(char) <= 0x9f for char in host):
        raise InvalidAddress('host name contains whitespace or control '
                             'characters')
    try:
        name = host.encode('idna') if not host.isascii() else host.encode('ascii')
    except UnicodeError:
        raise InvalidAddress('host name is not valid IDNA')
    _validate_domain_bytes(name)
    return name


def encode_address(host, port):
    """Encode (host, port) using the SOCKS5 address layout.

    Literal IPs are packed directly. Other hosts are validated and encoded as
    names for the server to resolve.
    """
    if not 0 <= port <= 0xFFFF:
        raise InvalidAddress('port %r is out of range' % (port,))
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        name = _encode_domain_name(host)
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
        _validate_domain_bytes(raw)
        try:
            host = raw.decode('idna')
        except UnicodeError:
            raise InvalidAddress('domain name is not valid IDNA')
        # Validate the decoded form too, guarding against any codec mapping
        # that introduces a resolver-significant character.
        _encode_domain_name(host)
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

    Only globally routable unicast addresses are safe by default. Private,
    shared, loopback, link-local, unspecified, reserved, documentation and
    multicast ranges can all name infrastructure that a holder of a connection
    string should not inherit access to.

    ``address`` is an ``ipaddress`` object or a string; an IPv4-mapped IPv6
    address is unmapped first, since ``::ffff:127.0.0.1`` reaches the same
    place ``127.0.0.1`` does.
    """
    if not isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        address = ipaddress.ip_address(address)
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    # ``ipaddress`` classification tables evolve between Python releases, and
    # ``is_global`` alone has historically included multicast, reserved IPv6
    # blocks and deprecated site-local space. Spell out every unsafe property
    # as well as retaining the conservative global-unicast requirement.
    return (not address.is_global
            or address.is_reserved
            or getattr(address, 'is_site_local', False)
            or address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
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

    def can_match_resolved_address(self, port):
        """Whether resolution could make this rule match ``port``.

        Name rules only match the name the client requested. Network rules
        cannot be decided until that name has been resolved.
        """
        return (self.network is not None
                and (self.port is None or self.port == port))


class AllowRules:
    """The destinations a server is willing to dial.

    With no rules, only globally routable unicast destinations are reachable.
    The policy is checked both on what the client asked for and on what a name
    resolved to, so a public-looking name cannot walk around it.

    With one or more rules, only what they name is reachable. An explicit IP
    address or CIDR is the sole way to opt a non-global destination back in --
    ``--allow 127.0.0.1:8081`` publishes one local service. A hostname pattern
    and ``any`` still require its resolved address to be globally routable,
    unless a separate IP/CIDR rule also permits that address.
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
            return 'globally routable unicast destinations'
        description = ', '.join(rule.text for rule in self._rules)
        if any(rule.any or rule.pattern is not None for rule in self._rules):
            description += (' (names may resolve only to globally routable '
                            'addresses unless an IP/CIDR rule opts one in)')
        return description

    def _matches(self, host, port):
        return any(rule.matches(host, port) for rule in self._rules)

    def check(self, host, port):
        """The status for a request naming ``host:port``, before resolution.

        :data:`SUCCEEDED` means "carry on and resolve"; anything else is the
        OPEN_RESULT to send back.
        """
        if self._rules:
            return SUCCEEDED if self._matches(host, port) else NOT_ALLOWED
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            # A name: the default policy can only be applied once it resolves.
            return SUCCEEDED
        return NOT_ALLOWED if is_restricted(address) else SUCCEEDED

    def _could_allow_after_resolution(self, host, port):
        """Whether a rejected name could be permitted by an address rule.

        This does not itself permit the destination. It only prevents the
        pre-resolution check from rejecting a name before its address rules
        can be evaluated by :meth:`check_resolved`.
        """
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return any(rule.can_match_resolved_address(port)
                       for rule in self._rules)
        return False

    def check_resolved(self, host, port, address):
        """The status for one address ``host`` resolved to.

        Only an address/CIDR rule can vouch for a non-global result. A hostname
        or ``any`` rule authorizes the requested name, not wherever DNS happens
        to point it today. This keeps ``--allow *.example.com`` from becoming
        an internal-network route after a DNS change or rebinding response.
        """
        if self._rules:
            # Check address rules first: they are an operator's explicit opt-in
            # to this exact address or network, including private ranges.
            for rule in self._rules:
                if (rule.network is not None
                        and rule.matches(str(address), port)):
                    return SUCCEEDED
            # Name/any rules still need to match the request, and their DNS
            # result receives the safe default classification.
            if self._matches(host, port):
                return NOT_ALLOWED if is_restricted(address) else SUCCEEDED
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
    """Resolve and dial host:port under rules; return (status, socket).

    The socket is None on failure. Check each resolved address before dialing and
    skip forbidden candidates. timeout applies to each socket connect, not DNS
    resolution or the total time across candidates.
    """
    # This function is also part of the Python API, so do not rely only on the
    # wire decoder having validated a domain.  In particular, libc resolvers
    # treat a NUL as the end of a name while an allow-rule matcher sees the
    # suffix after it.  Refuse every resolver-ambiguous name before either the
    # policy check or getaddrinfo sees it.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            _encode_domain_name(host)
        except InvalidAddress:
            return NOT_ALLOWED, None
    except TypeError:
        return NOT_ALLOWED, None

    status = rules.check(host, port)
    if (status != SUCCEEDED
            and not rules._could_allow_after_resolution(host, port)):
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
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            sock.close()
            last = status_for_error(e)
            continue
        return SUCCEEDED, sock

    if refused_by_policy and last == GENERAL_FAILURE:
        return NOT_ALLOWED, None
    return last, None
