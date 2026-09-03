#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Realism check for the ``ftp`` control-channel format (phase F-ftp).

FTP's control channel (RFC 959) is a cleartext line protocol: the client sends
a command -- an uppercase verb, optionally a space and an argument, terminated
by CRLF -- and the server answers with a three-digit reply code, a space, some
human-readable text, and CRLF. :func:`check` judges a single sealed covertext
the way a DPI box scanning port 21 would: it insists on exactly one CRLF-ended
line whose shape is a known FTP command *or* a known reply, rejecting anything
else.

This is a strict, self-contained grammar check. It shares no code with the
other protocol realism modules and does not import the ``parts/ftp.json`` regex
-- it re-derives the structure by hand so a covertext that only *happens* to
match the sampling regex still has to stand on its own as a well-formed FTP
message.
"""


class FTPRealismError(Exception):
    """A covertext is not a structurally valid FTP control-channel message."""


# Commands that take a (non-empty) argument on the control channel.
_ARG_VERBS = frozenset((b'USER', b'PASS', b'CWD', b'RETR', b'STOR', b'LIST'))

# Commands that stand alone with no argument.
_BARE_VERBS = frozenset((b'PASV', b'QUIT'))

# The reply codes this format models, as byte strings.
_REPLY_CODES = frozenset((b'220', b'230', b'331', b'250',
                          b'150', b'226', b'550'))

# Characters allowed in a command argument (usernames, paths, filenames):
# ASCII letters and digits plus a small set of path/name punctuation. No space
# -- an FTP argument is a single token.
_ARG_CHARS = frozenset(
    b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._@/-')

# Characters allowed in reply text: printable ASCII words with spacing and a
# little punctuation. No control bytes.
_TEXT_CHARS = frozenset(
    b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,:()/-')


def _fail(reason, covertext):
    raise FTPRealismError('%s: %r' % (reason, covertext[:64]))


def check(covertext):
    """Raise :class:`FTPRealismError` unless ``covertext`` is a valid FTP line.

    Accepts either a client command or a server reply; returns ``None`` on a
    structurally valid message.
    """
    if not isinstance(covertext, (bytes, bytearray)):
        _fail('covertext is not bytes', covertext)
    covertext = bytes(covertext)

    if not covertext.endswith(b'\r\n'):
        _fail('does not end with CRLF', covertext)
    line = covertext[:-2]

    # Exactly one line: no embedded CR or LF anywhere in the payload.
    if b'\r' in line or b'\n' in line:
        _fail('contains an embedded CR or LF', covertext)
    if not line:
        _fail('empty line', covertext)

    # A reply begins with three ASCII digits; a command begins with a letter.
    first = line[0:1]
    if first.isdigit():
        _check_reply(line, covertext)
    else:
        _check_command(line, covertext)


def _check_command(line, covertext):
    """A client command: a bare verb, or a verb SP non-empty-token argument."""
    if b' ' in line:
        verb, _, arg = line.partition(b' ')
        if verb == b'TYPE':
            # TYPE takes exactly one representation code.
            if arg not in (b'A', b'I'):
                _fail('TYPE argument is not A or I', covertext)
            return
        if verb not in _ARG_VERBS:
            _fail('unknown command verb %r' % verb, covertext)
        if not arg:
            _fail('%r command with empty argument' % verb, covertext)
        if b' ' in arg:
            _fail('%r argument contains a space' % verb, covertext)
        if any(byte not in _ARG_CHARS for byte in arg):
            _fail('%r argument has a disallowed byte' % verb, covertext)
        return

    # No space: only the argument-less verbs are valid on their own.
    if line not in _BARE_VERBS:
        _fail('bare command is not PASV or QUIT', covertext)


def _check_reply(line, covertext):
    """A server reply: a known 3-digit code, a space, non-empty text."""
    if len(line) < 5:
        _fail('reply too short for "code SP text"', covertext)
    code = line[0:3]
    if code not in _REPLY_CODES:
        _fail('unknown reply code %r' % code, covertext)
    if line[3:4] != b' ':
        _fail('reply code not followed by a single space', covertext)
    text = line[4:]
    if not text:
        _fail('reply has empty text', covertext)
    if any(byte not in _TEXT_CHARS for byte in text):
        _fail('reply text has a disallowed byte', covertext)
