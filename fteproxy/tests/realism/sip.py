#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check selected SIP/2.0 start-line and header properties.

Parse start lines directly and headers with email.parser, independently of the
format regex. Check selected methods/statuses, required header presence,
character sets, branch cookies, and declared body length when present.

This is not a full SIP validator: hostname syntax, CSeq bounds and agreement
with the request method, and transaction relationships are not enforced.
"""

import email.parser


class SIPRealismError(Exception):
    """A covertext failed the selected SIP structure checks."""


#: Methods the format models, in the request line and in ``CSeq``.
_METHODS = ('INVITE', 'REGISTER', 'ACK', 'BYE', 'OPTIONS')

# Modeled status/reason pairs; SIP allows other reason text.
_STATUS = {'100': 'Trying', '180': 'Ringing', '200': 'OK', '404': 'Not Found'}

#: RFC 3261 requires every compliant branch parameter to start with this cookie.
_MAGIC_COOKIE = 'z9hG4bK'

_VERSION = 'SIP/2.0'
_TRANSPORT = _VERSION + '/TCP '

#: Headers that must appear in every SIP request and response (RFC 3261 8.1.1).
_MANDATORY_HEADERS = ('Via', 'From', 'To', 'Call-ID', 'CSeq')

# Character classes, spelled out so this module owns its own grammar.
_DIGITS = set('0123456789')
_ALNUM = set('abcdefghijklmnopqrstuvwxyz'
             'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
             '0123456789')
#: The user part of a ``sip:`` URI.
_USER = set('abcdefghijklmnopqrstuvwxyz0123456789._-')
# Allowed host-field bytes; this check does not validate hostname syntax.
_HOST = set('abcdefghijklmnopqrstuvwxyz0123456789.-')


def _require(condition, message, *args):
    if not condition:
        raise SIPRealismError(message % args if args else message)


def _all_in(chunk, allowed, what):
    _require(len(chunk) > 0, 'empty %s', what)
    for character in chunk:
        _require(character in allowed,
                 '%s %r contains %r, which is outside its character set',
                 what, chunk, character)


def _check_uri(uri, what):
    """``sip:user@host`` -- the bare URI form, without angle brackets."""
    _require(uri.startswith('sip:'), '%s %r is not a sip: URI', what, uri)
    userinfo = uri[len('sip:'):]
    _require(userinfo.count('@') == 1,
             '%s %r is not sip:user@host', what, uri)
    user, host = userinfo.split('@', 1)
    _all_in(user, _USER, '%s user part' % what)
    _all_in(host, _HOST, '%s host part' % what)


def _check_bracketed_uri(value, what):
    """``<sip:user@host>`` -- the name-addr form used by ``From`` and ``To``."""
    _require(value.startswith('<') and value.endswith('>'),
             '%s %r is not a bracketed name-addr', what, value)
    _check_uri(value[1:-1], what)


# --------------------------------------------------------------------------- #
# Start lines
# --------------------------------------------------------------------------- #

def _check_request_line(line):
    parts = line.split(' ')
    _require(len(parts) == 3,
             'request line %r is not METHOD SP Request-URI SP SIP-Version',
             line)
    method, uri, version = parts
    _require(method in _METHODS, 'unexpected request method %r', method)
    _check_uri(uri, 'request-URI')
    _require(version == _VERSION,
             'request version %r is not %s', version, _VERSION)
    return method


def _check_status_line(line):
    version, separator, rest = line.partition(' ')
    _require(separator, 'status line %r has no space after the version', line)
    _require(version == _VERSION,
             'status version %r is not %s', version, _VERSION)
    code, separator, reason = rest.partition(' ')
    _require(separator, 'status line %r has no reason phrase', line)
    _require(len(code) == 3 and set(code) <= _DIGITS,
             'status code %r is not three digits', code)
    _require(code in _STATUS, 'unexpected status code %r', code)
    _require(reason == _STATUS[code],
             'status %s has reason %r, not %r', code, reason, _STATUS[code])
    return code


# --------------------------------------------------------------------------- #
# Headers
# --------------------------------------------------------------------------- #

def _check_via(value):
    _require(value.startswith(_TRANSPORT),
             'Via %r does not start with %r', value, _TRANSPORT)
    rest = value[len(_TRANSPORT):]
    host, separator, parameters = rest.partition(';')
    _require(separator, 'Via %r carries no parameters', value)
    _all_in(host, _HOST, 'Via sent-by host')
    name, separator, branch = parameters.partition('=')
    _require(separator and name == 'branch',
             'Via parameter %r is not a branch', parameters)
    _require(branch.startswith(_MAGIC_COOKIE),
             'Via branch %r lacks the RFC 3261 magic cookie %r',
             branch, _MAGIC_COOKIE)
    _all_in(branch[len(_MAGIC_COOKIE):], _ALNUM, 'Via branch token')


def _check_from(value):
    address, separator, parameters = value.partition(';')
    _require(separator, 'From %r carries no tag parameter', value)
    _check_bracketed_uri(address, 'From')
    name, separator, tag = parameters.partition('=')
    _require(separator and name == 'tag',
             'From parameter %r is not a tag', parameters)
    _all_in(tag, _ALNUM, 'From tag')


def _check_to(value):
    _check_bracketed_uri(value, 'To')


def _check_call_id(value):
    _require(value.count('@') == 1, 'Call-ID %r is not token@host', value)
    token, host = value.split('@', 1)
    _all_in(token, _ALNUM, 'Call-ID token')
    _all_in(host, _HOST, 'Call-ID host')


def _check_cseq(value):
    number, separator, method = value.partition(' ')
    _require(separator, 'CSeq %r has no method', value)
    _all_in(number, _DIGITS, 'CSeq sequence number')
    _require(method in _METHODS, 'CSeq method %r is unexpected', method)


_HEADER_CHECKS = {
    'Via': _check_via,
    'From': _check_from,
    'To': _check_to,
    'Call-ID': _check_call_id,
    'CSeq': _check_cseq,
}


def _check_headers(block):
    """Parse the header block with :mod:`email.parser` and vet each header."""
    message = email.parser.BytesParser().parsebytes(block)
    _require(not message.defects,
             'malformed SIP header block: %r', message.defects)

    for name in _MANDATORY_HEADERS:
        value = message.get(name)
        _require(value is not None, 'missing mandatory %s header', name)
        _HEADER_CHECKS[name](value)

    length = message.get('Content-Length')
    if length is not None:
        _all_in(length, _DIGITS, 'Content-Length')
        body = message.get_payload()
        _require(len(body) == int(length),
                 'Content-Length %s does not match a %d-byte body',
                 length, len(body))


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def check(covertext):
    """Raise SIPRealismError if a covertext fails the selected SIP checks."""
    if not isinstance(covertext, (bytes, bytearray)):
        raise SIPRealismError('covertext is not bytes: %r' % (type(covertext),))
    covertext = bytes(covertext)

    _require(covertext.endswith(b'\r\n\r\n'),
             'covertext does not end with a blank line terminating the headers')

    start_line, separator, block = covertext.partition(b'\r\n')
    _require(separator, 'covertext has no CRLF after the start line')
    try:
        line = start_line.decode('ascii')
    except UnicodeDecodeError:
        raise SIPRealismError('start line %r is not ASCII' % (start_line,))
    _require('\r' not in line and '\n' not in line,
             'bare CR/LF inside the start line')

    if line.startswith(_VERSION + ' '):
        _check_status_line(line)
    else:
        _check_request_line(line)

    _check_headers(block)
