#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Structural realism check for the ``imap`` format (phase F4).

IMAP4rev1 (RFC 3501) is a cleartext, line-oriented protocol: every message is a
CRLF-terminated line, a client command carries a ``a<n>`` tag and a verb, and a
server line is either untagged (``*``) or a tagged completion. :func:`check`
judges a sealed covertext the way a DPI grammar would -- an independent,
token-by-token parse of one line, not a re-run of the format's own regex -- and
raises on anything that is not a structurally valid IMAP command or response.

It imports nothing from the other protocol realism modules.
"""

import re


class RealismError(Exception):
    """A covertext is not a structurally valid IMAP message."""


# Per-field character classes, anchored so a field is validated whole. These
# mirror the grammar the format's regex draws from, but the parse below walks
# the line production by production rather than matching one monolithic pattern.
_TAG = re.compile(rb'a[0-9]+\Z')
_DIGITS = re.compile(rb'[0-9]+\Z')
_USER = re.compile(rb'[a-z][a-z0-9._-]*\Z')
_PASS = re.compile(rb'[A-Za-z0-9!#$%&*+._-]+\Z')
_MAILBOX = re.compile(rb'[A-Za-z][A-Za-z0-9/._-]*\Z')
_RANGE = re.compile(rb'[0-9]+:[0-9]+\Z')
_SECTION = re.compile(rb'\(FLAGS BODY\[[A-Z.]*\]\)\Z')
_STORE_FLAGS = re.compile(rb'[+-]FLAGS \(\\[A-Za-z]+\)\Z')
_SEARCH_TERM = re.compile(rb'[A-Za-z0-9 ._@-]+\Z')
_STATUS_TEXT = re.compile(rb'[A-Za-z0-9 .,;:()_@/-]+\Z')

_STATUS = (b'OK', b'NO', b'BAD')
_SEARCH_KEYS = (b'FROM', b'TO', b'SUBJECT', b'BODY')
_COUNTERS = (b'EXISTS', b'RECENT')


def _match(pattern, field, what):
    if not pattern.fullmatch(field):
        raise RealismError('malformed %s: %r' % (what, field))


def _check_command(tag, rest):
    """A tagged client command: ``<tag> SP <verb> [SP <args>]``."""
    _match(_TAG, tag, 'command tag')
    verb, sep, args = rest.partition(b' ')

    if verb == b'LOGIN':
        user, usep, password = args.partition(b' ')
        if not usep:
            raise RealismError('LOGIN needs a user and a password')
        _match(_USER, user, 'LOGIN user')
        _match(_PASS, password, 'LOGIN password')
    elif verb == b'SELECT':
        _match(_MAILBOX, args, 'SELECT mailbox')
    elif verb == b'FETCH':
        seq_set, ssep, section = args.partition(b' ')
        if not ssep:
            raise RealismError('FETCH needs a sequence set and a section')
        _match(_RANGE, seq_set, 'FETCH sequence set')
        _match(_SECTION, section, 'FETCH section')
    elif verb == b'STORE':
        seq_set, ssep, flags = args.partition(b' ')
        if not ssep:
            raise RealismError('STORE needs a sequence set and flags')
        _match(_DIGITS, seq_set, 'STORE sequence number')
        _match(_STORE_FLAGS, flags, 'STORE flags')
    elif verb == b'SEARCH':
        key, ksep, term = args.partition(b' ')
        if not ksep or key not in _SEARCH_KEYS:
            raise RealismError('SEARCH needs a known key and a term: %r' % rest)
        _match(_SEARCH_TERM, term, 'SEARCH term')
    elif verb == b'LOGOUT':
        if sep or args:
            raise RealismError('LOGOUT takes no arguments: %r' % rest)
    else:
        raise RealismError('unknown IMAP command verb: %r' % verb)


def _check_untagged(rest):
    """An untagged server line: ``* <status> <text>`` or ``* <n> <counter>``."""
    first, sep, remainder = rest.partition(b' ')
    if not sep:
        raise RealismError('untagged line has no payload: %r' % rest)
    if first in _STATUS:
        _match(_STATUS_TEXT, remainder, 'status response text')
    elif _DIGITS.fullmatch(first):
        if remainder not in _COUNTERS:
            raise RealismError('unknown mailbox counter: %r' % remainder)
    else:
        raise RealismError('unrecognized untagged response: %r' % rest)


def check(covertext):
    """Raise if ``covertext`` is not one structurally valid IMAP message.

    Accepts either direction: a tagged client command or a server response
    (untagged status/counter line or tagged completion). Returns ``None`` on a
    valid message.
    """
    if not isinstance(covertext, (bytes, bytearray)):
        raise RealismError('covertext must be bytes, got %r' % type(covertext))
    if not covertext.endswith(b'\r\n'):
        raise RealismError('IMAP line is not CRLF-terminated')
    line = bytes(covertext[:-2])
    if b'\r' in line or b'\n' in line:
        raise RealismError('embedded CR/LF in an IMAP line')
    if not line:
        raise RealismError('empty IMAP line')

    if line.startswith(b'* '):
        _check_untagged(line[2:])
        return

    tag, sep, rest = line.partition(b' ')
    if not sep:
        raise RealismError('IMAP line has no space after its tag: %r' % line)
    # A tagged line is a server completion when its verb is a status word, and a
    # client command otherwise; both share the ``a<n>`` tag shape.
    verb = rest.partition(b' ')[0]
    if verb in _STATUS:
        _match(_TAG, tag, 'completion tag')
        _check_untagged(rest)
        return
    _check_command(tag, rest)
