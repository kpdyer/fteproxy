#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for OPEN/OPEN_RESULT encoding, address classification and allow rules."""

import ipaddress
import socket

import pytest

import fteproxy.stream as stream


class TestAddressEncoding:
    """SOCKS5's encoding, so a request crosses the tunnel unaltered."""

    @pytest.mark.parametrize('host,port,atyp', [
        ('192.0.2.1', 443, stream.ATYP_IPV4),
        ('0.0.0.0', 0, stream.ATYP_IPV4),
        ('255.255.255.255', 65535, stream.ATYP_IPV4),
        ('2001:db8::1', 8080, stream.ATYP_IPV6),
        ('::1', 22, stream.ATYP_IPV6),
        ('example.com', 80, stream.ATYP_DOMAIN),
        ('a', 1, stream.ATYP_DOMAIN),
        ('sub.domain.example.org', 65535, stream.ATYP_DOMAIN),
    ])
    def test_round_trip(self, host, port, atyp):
        encoded = stream.encode_address(host, port)
        assert encoded[0] == atyp
        assert stream.decode_address(encoded) == (host, port)

    def test_a_long_name_is_encoded(self):
        host = '.'.join(['a' * 40] * 6)[:250]
        assert stream.decode_address(stream.encode_address(host, 1)) == (host, 1)

    def test_a_name_over_255_bytes_is_refused(self):
        with pytest.raises(stream.InvalidAddress):
            stream.encode_address('a' * 256, 80)

    @pytest.mark.parametrize('port', [-1, 65536, 1 << 20])
    def test_port_range(self, port):
        with pytest.raises(stream.InvalidAddress):
            stream.encode_address('example.com', port)

    def test_trailing_bytes_are_refused(self):
        with pytest.raises(stream.InvalidAddress):
            stream.decode_address(stream.encode_address('example.com', 80)
                                  + b'\x00')

    def test_truncated_is_refused(self):
        encoded = stream.encode_address('example.com', 80)
        for cut in range(len(encoded)):
            with pytest.raises(stream.InvalidAddress):
                stream.decode_address(encoded[:cut])

    def test_unknown_address_type_is_refused(self):
        with pytest.raises(stream.InvalidAddress):
            stream.decode_address(b'\x09' + b'\x00' * 6)

    def test_empty_domain_is_refused(self):
        with pytest.raises(stream.InvalidAddress):
            stream.decode_address(bytes((stream.ATYP_DOMAIN, 0)) + b'\x00\x50')

    def test_read_address_reports_its_end(self):
        encoded = stream.encode_address('192.0.2.1', 80)
        host, port, end = stream.read_address(encoded + b'trailing')
        assert (host, port) == ('192.0.2.1', 80)
        assert end == len(encoded)


class TestOpenResult:

    @pytest.mark.parametrize('status', [0x00, 0x02, 0x05, 0xFF])
    def test_round_trip(self, status):
        assert stream.decode_open_result(
            stream.encode_open_result(status)) == status

    @pytest.mark.parametrize('payload', [b'', b'\x00\x00'])
    def test_wrong_width_is_refused(self, payload):
        with pytest.raises(stream.InvalidAddress):
            stream.decode_open_result(payload)

    def test_every_status_has_a_name(self):
        for status in range(0x00, 0x09):
            assert 'status 0x' not in stream.status_name(status)


class TestRestrictedAddresses:

    @pytest.mark.parametrize('address', [
        '127.0.0.1', '127.1.2.3', '::1',
        '169.254.1.1', 'fe80::1',
        '0.0.0.0', '::',
        '::ffff:127.0.0.1',      # an IPv4-mapped loopback reaches loopback
        '::ffff:169.254.0.1',
    ])
    def test_restricted(self, address):
        assert stream.is_restricted(address)

    @pytest.mark.parametrize('address', [
        '8.8.8.8', '192.0.2.1', '10.0.0.1', '2001:db8::1',
        '::ffff:192.0.2.1',
    ])
    def test_permitted(self, address):
        assert not stream.is_restricted(address)

    def test_accepts_an_ipaddress_object(self):
        assert stream.is_restricted(ipaddress.ip_address('127.0.0.1'))


class TestAllowRules:
    """The table the plan asks for: what each rule shape does and does not
    permit."""

    def rules(self, *specs):
        return stream.AllowRules(specs)

    def test_no_rules_permits_a_public_address(self):
        assert self.rules().check('192.0.2.1', 443) == stream.SUCCEEDED

    def test_no_rules_refuses_loopback_and_link_local(self):
        for host in ('127.0.0.1', '::1', '169.254.1.1', '0.0.0.0'):
            assert self.rules().check(host, 8080) == stream.NOT_ALLOWED

    def test_no_rules_defers_on_a_name(self):
        """A name cannot be classified before it resolves, so the default
        policy is applied again once it has."""
        default = self.rules()
        assert default.check('localhost', 8080) == stream.SUCCEEDED
        assert default.check_resolved(
            'localhost', 8080,
            ipaddress.ip_address('127.0.0.1')) == stream.NOT_ALLOWED

    def test_any_permits_everything_including_loopback(self):
        rules = self.rules('any')
        assert rules.check('127.0.0.1', 22) == stream.SUCCEEDED
        assert rules.check_resolved(
            'localhost', 22, ipaddress.ip_address('127.0.0.1')) == \
            stream.SUCCEEDED

    def test_rules_are_a_whitelist(self):
        rules = self.rules('192.0.2.1:443')
        assert rules.check('192.0.2.1', 443) == stream.SUCCEEDED
        assert rules.check('192.0.2.1', 80) == stream.NOT_ALLOWED
        assert rules.check('198.51.100.1', 443) == stream.NOT_ALLOWED

    def test_a_rule_without_a_port_permits_every_port(self):
        rules = self.rules('192.0.2.1')
        assert rules.check('192.0.2.1', 1) == stream.SUCCEEDED
        assert rules.check('192.0.2.1', 65535) == stream.SUCCEEDED

    def test_a_local_service_can_be_published(self):
        """The plan's example: --allow 127.0.0.1:8081 opts one service in."""
        rules = self.rules('127.0.0.1:8081')
        assert rules.check('127.0.0.1', 8081) == stream.SUCCEEDED
        assert rules.check_resolved(
            '127.0.0.1', 8081,
            ipaddress.ip_address('127.0.0.1')) == stream.SUCCEEDED
        assert rules.check('127.0.0.1', 22) == stream.NOT_ALLOWED

    def test_cidr(self):
        rules = self.rules('10.0.0.0/8:443')
        assert rules.check('10.1.2.3', 443) == stream.SUCCEEDED
        assert rules.check('10.1.2.3', 80) == stream.NOT_ALLOWED
        assert rules.check('11.1.2.3', 443) == stream.NOT_ALLOWED

    def test_ipv6_cidr_needs_brackets_for_a_port(self):
        rules = self.rules('[2001:db8::/32]:443')
        assert rules.check('2001:db8::1', 443) == stream.SUCCEEDED
        assert rules.check('2001:db8::1', 444) == stream.NOT_ALLOWED
        assert rules.check('2001:dba::1', 443) == stream.NOT_ALLOWED

    def test_bare_ipv6_without_a_port(self):
        rules = self.rules('2001:db8::1')
        assert rules.check('2001:db8::1', 9999) == stream.SUCCEEDED
        assert rules.check('2001:db8::2', 9999) == stream.NOT_ALLOWED

    def test_wildcard_name(self):
        rules = self.rules('*.example.com:443')
        assert rules.check('www.example.com', 443) == stream.SUCCEEDED
        assert rules.check('WWW.EXAMPLE.COM', 443) == stream.SUCCEEDED
        assert rules.check('example.com', 443) == stream.NOT_ALLOWED
        assert rules.check('www.example.org', 443) == stream.NOT_ALLOWED

    def test_exact_name(self):
        rules = self.rules('example.com')
        assert rules.check('example.com', 80) == stream.SUCCEEDED
        assert rules.check('www.example.com', 80) == stream.NOT_ALLOWED

    def test_a_name_rule_does_not_vouch_for_an_address(self):
        """The two are different questions: a name rule cannot say where that
        name points today."""
        rules = self.rules('example.com')
        assert rules.check('192.0.2.1', 80) == stream.NOT_ALLOWED

    def test_an_address_rule_does_not_match_a_name(self):
        rules = self.rules('192.0.2.1')
        assert rules.check('example.com', 80) == stream.NOT_ALLOWED

    def test_an_address_rule_vouches_for_a_name_that_resolves_to_it(self):
        """This is what makes --allow 127.0.0.1:8081 usable through a name."""
        rules = self.rules('127.0.0.1:8081')
        assert rules.check_resolved(
            'localhost', 8081,
            ipaddress.ip_address('127.0.0.1')) == stream.SUCCEEDED

    def test_ipv4_mapped_requests_are_unmapped(self):
        rules = self.rules('192.0.2.0/24')
        assert rules.check('::ffff:192.0.2.9', 80) == stream.SUCCEEDED

    @pytest.mark.parametrize('spec', [
        '', ':80', 'example.com:0', 'example.com:70000',
        'example.com:http', '[2001:db8::1', '[2001:db8::1]80',
    ])
    def test_bad_rules_are_refused(self, spec):
        with pytest.raises(stream.InvalidRule):
            stream.AllowRules([spec])

    def test_describe(self):
        assert 'loopback' in stream.AllowRules().describe()
        assert stream.AllowRules(['any']).describe() == 'any'


class TestStatusForError:

    def test_refused(self):
        import errno

        error = ConnectionRefusedError()
        error.errno = errno.ECONNREFUSED
        assert stream.status_for_error(error) == stream.CONNECTION_REFUSED

    @pytest.mark.parametrize('name,expected', [
        ('ENETUNREACH', stream.NETWORK_UNREACHABLE),
        ('EHOSTUNREACH', stream.HOST_UNREACHABLE),
        ('ETIMEDOUT', stream.TTL_EXPIRED),
    ])
    def test_errno_mapping(self, name, expected):
        import errno

        error = OSError()
        error.errno = getattr(errno, name)
        assert stream.status_for_error(error) == expected

    def test_resolution_failure(self):
        assert stream.status_for_error(socket.gaierror()) == \
            stream.HOST_UNREACHABLE

    def test_timeout(self):
        assert stream.status_for_error(socket.timeout()) == stream.TTL_EXPIRED

    def test_unknown(self):
        assert stream.status_for_error(OSError()) == stream.GENERAL_FAILURE


class TestConnect:
    """The dial path, including the checks that run after resolution."""

    def test_refuses_a_blocked_address_without_dialling(self):
        status, sock = stream.connect('127.0.0.1', 9, stream.AllowRules(), 1)
        assert status == stream.NOT_ALLOWED
        assert sock is None

    def test_refuses_a_name_that_resolves_into_the_block(self):
        """localhost is the reason the policy is checked twice."""
        status, sock = stream.connect('localhost', 9, stream.AllowRules(), 1)
        assert status == stream.NOT_ALLOWED
        assert sock is None

    def test_refused_port_maps_to_connection_refused(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()
        status, sock = stream.connect(
            '127.0.0.1', port, stream.AllowRules(['127.0.0.1']), 5)
        assert status == stream.CONNECTION_REFUSED
        assert sock is None

    def test_success(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            status, sock = stream.connect(
                '127.0.0.1', port, stream.AllowRules(['127.0.0.1']), 5)
            assert status == stream.SUCCEEDED
            assert sock is not None
            sock.close()
        finally:
            listener.close()

    def test_unresolvable_name(self):
        status, sock = stream.connect(
            'no-such-host.invalid', 80, stream.AllowRules(['any']), 5)
        assert status in (stream.HOST_UNREACHABLE, stream.GENERAL_FAILURE)
        assert sock is None
