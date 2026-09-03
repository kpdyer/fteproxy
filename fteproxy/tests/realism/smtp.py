#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Structural realism check for the ``smtp`` format (phase F5).

SMTP is a cleartext, line-oriented protocol: a client sends command lines
(``EHLO host``, ``MAIL FROM:<addr>``, ``RCPT TO:<addr>``, ``DATA``, ``QUIT``,
...) and a server answers with reply lines (``250 OK``, ``220 host ESMTP``,
``354 ...``, ``550 ...``), every line terminated by CRLF (RFC 5321). One sealed
covertext of the ``smtp-request``/``smtp-response`` formats is exactly one such
line.

:func:`check` judges a covertext with a hand-written grammar, independent of the
format's own regex (the format regex must not be imported here), and accepts a
line that is a valid client command *or* a valid server reply, since the batch a
test feeds it mixes both roles. It raises on anything that is not a
structurally valid SMTP line.
"""


class SMTPRealismError(Exception):
    """A covertext is not a structurally valid SMTP command or reply line."""


# Character classes, spelled out as byte sets so the check owns its own grammar
# rather than leaning on the format regex.
_DIGITS = set(b'0123456789')
_LOWER = set(b'abcdefghijklmnopqrstuvwxyz')
_UPPER = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
_LETTERS = _LOWER | _UPPER
# Host label bytes: lowercase letters, digits, dot and hyphen (RFC 1035 style).
_HOST = _LOWER | _DIGITS | set(b'.-')
# Local-part bytes of an address: letters, digits and the common local
# specials SMTP addresses use in practice.
_LOCAL = _LOWER | _DIGITS | set(b'._%+-')
# Free-text reply bytes: printable ASCII an SMTP reply line uses, minus CR/LF.
_TEXT = _LETTERS | _DIGITS | set(b' .,;:()<>@_-')

# Reply codes the format models, by leading digit family.
_REPLY_CODES = {b'220', b'250', b'354', b'421', b'550'}

# Fixed client verbs that take no argument.
_BARE_VERBS = {b'DATA', b'RSET', b'NOOP', b'QUIT'}


def _all_in(chunk, allowed):
    return len(chunk) > 0 and all(byte in allowed for byte in chunk)


def _check_host(host):
    if not _all_in(host, _HOST):
        raise SMTPRealismError('invalid host %r' % (host,))
    # A hostname is a non-empty run of the allowed bytes; reject a leading or
    # trailing dot/hyphen so it is not a degenerate punctuation-only string.
    if host[0:1] in (b'.', b'-') or host[-1:] in (b'.', b'-'):
        raise SMTPRealismError('host %r starts or ends with a separator' % (host,))


def _check_address(addr):
    # ``local@domain`` with exactly one ``@`` splitting the two halves.
    if addr.count(b'@') != 1:
        raise SMTPRealismError('address %r is not local@domain' % (addr,))
    local, domain = addr.split(b'@', 1)
    if not _all_in(local, _LOCAL):
        raise SMTPRealismError('invalid local-part %r' % (local,))
    _check_host(domain)


def _check_command(line):
    """Raise unless ``line`` (no CRLF) is a valid client command."""
    if line in _BARE_VERBS:
        return
    for verb in (b'EHLO ', b'HELO '):
        if line.startswith(verb):
            _check_host(line[len(verb):])
            return
    if line.startswith(b'VRFY '):
        arg = line[len(b'VRFY '):]
        if not _all_in(arg, _LOCAL):
            raise SMTPRealismError('invalid VRFY argument %r' % (arg,))
        return
    for verb, path in ((b'MAIL FROM:', b'from'), (b'RCPT TO:', b'to')):
        if line.startswith(verb):
            rest = line[len(verb):]
            if not (rest.startswith(b'<') and rest.endswith(b'>')):
                raise SMTPRealismError('%s path not bracketed: %r' % (path, rest))
            _check_address(rest[1:-1])
            return
    raise SMTPRealismError('unrecognized command line %r' % (line,))


def _check_reply(line):
    """Raise unless ``line`` (no CRLF) is a valid server reply line."""
    if len(line) < 4:
        raise SMTPRealismError('reply line too short: %r' % (line,))
    code, sep, text = line[:3], line[3:4], line[4:]
    if code not in _REPLY_CODES:
        raise SMTPRealismError('unknown reply code %r' % (code,))
    # A space separates a final reply line; a hyphen marks a continuation line.
    if sep not in (b' ', b'-'):
        raise SMTPRealismError('reply separator %r is not " " or "-"' % (sep,))
    if not _all_in(text, _TEXT):
        raise SMTPRealismError('reply text has non-text bytes: %r' % (text,))


def check(covertext):
    """Raise :class:`SMTPRealismError` unless ``covertext`` is a valid SMTP line.

    A valid covertext is a single command or reply line terminated by exactly
    one trailing CRLF, with no other CR or LF anywhere in the line.
    """
    if not isinstance(covertext, (bytes, bytearray)):
        raise SMTPRealismError('covertext is not bytes: %r' % (type(covertext),))
    covertext = bytes(covertext)
    if not covertext.endswith(b'\r\n'):
        raise SMTPRealismError('covertext does not end with CRLF')
    line = covertext[:-2]
    if b'\r' in line or b'\n' in line:
        raise SMTPRealismError('bare CR/LF inside the line')
    if not line:
        raise SMTPRealismError('empty SMTP line')
    # A reply line starts with a three-digit code; everything else is a command.
    if len(line) >= 3 and _all_in(line[:3], _DIGITS):
        _check_reply(line)
    else:
        _check_command(line)
