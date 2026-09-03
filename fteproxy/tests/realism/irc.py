#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Realism check for the ``irc`` format (phase F5).

IRC is a cleartext, line-oriented protocol (RFC 1459 / 2812): each message is a
single ``\\r\\n``-terminated line, either ``<command> <params>`` sent by a
client or a ``:<prefix> <numeric> <params>`` reply sent by a server. The format
is symmetric -- ``irc-request`` and ``irc-response`` share one line grammar --
so this one :func:`check` judges a covertext from either role.

Unlike ``http.py`` (which defers to ``http.server``/``email.parser``), a line
protocol has no stdlib parser, so this is a strict hand-written grammar: split a
line into command and parameters and validate each field against its character
class. It imports nothing from the other realism modules. A covertext that is
not a structurally valid IRC line raises :class:`IrcRealismError`.
"""

import re


class IrcRealismError(Exception):
    """A covertext is not a structurally valid IRC protocol line."""


# --------------------------------------------------------------------------- #
# Field grammars (anchored). These mirror the character classes of the format
# regex, but are written independently here as the structural judge.
# --------------------------------------------------------------------------- #

#: A nickname: a letter then letters/digits/underscore/hyphen.
_NICK = re.compile(rb'[A-Za-z][A-Za-z0-9_-]*\Z')
#: A channel: ``#`` then a lowercase-led run.
_CHANNEL = re.compile(rb'#[a-z][a-z0-9._-]*\Z')
#: A PRIVMSG/NOTICE target: a channel or a nickname.
_TARGET = re.compile(rb'(#[a-z][a-z0-9._-]*|[A-Za-z][A-Za-z0-9_-]*)\Z')
#: The rich trailing text of a PRIVMSG/NOTICE/PART/numeric.
_TEXT = re.compile(rb"[A-Za-z0-9 .,!?'()_-]+\Z")
#: A PING/PONG token (a server or cookie): no spaces.
_TOKEN = re.compile(rb'[A-Za-z0-9._-]+\Z')
#: The USER command's ``<username> <mode> *`` prefix before the realname.
_USER_PREFIX = re.compile(rb'[a-z][a-z0-9_-]* [0-9] \*\Z')
#: The USER command's realname (no IRC control punctuation).
_REALNAME = re.compile(rb'[A-Za-z0-9 ._-]+\Z')
#: A server prefix in a numeric reply.
_SERVER = re.compile(rb'[a-z][a-z0-9.-]*\Z')
#: A three-digit numeric reply code.
_NUMERIC = re.compile(rb'[0-9][0-9][0-9]\Z')


def _need(condition, message):
    if not condition:
        raise IrcRealismError(message)


def _check_nick_command(rest):
    _need(_NICK.fullmatch(rest), 'NICK: invalid nickname')


def _check_user_command(rest):
    # ``<username> <mode> * :<realname>`` -- realname may contain spaces.
    prefix, sep, realname = rest.partition(b' :')
    _need(sep, 'USER: missing realname')
    _need(_USER_PREFIX.fullmatch(prefix), 'USER: invalid username/mode prefix')
    _need(_REALNAME.fullmatch(realname), 'USER: invalid realname')


def _check_join_command(rest):
    _need(_CHANNEL.fullmatch(rest), 'JOIN: invalid channel')


def _check_part_command(rest):
    channel, sep, text = rest.partition(b' :')
    _need(sep, 'PART: missing part message')
    _need(_CHANNEL.fullmatch(channel), 'PART: invalid channel')
    _need(_TEXT.fullmatch(text), 'PART: invalid part message')


def _check_message_command(rest):
    # PRIVMSG/NOTICE ``<target> :<text>`` -- text may contain spaces.
    target, sep, text = rest.partition(b' :')
    _need(sep, 'PRIVMSG/NOTICE: missing text')
    _need(_TARGET.fullmatch(target), 'PRIVMSG/NOTICE: invalid target')
    _need(_TEXT.fullmatch(text), 'PRIVMSG/NOTICE: invalid text')


def _check_ping_command(rest):
    _need(rest.startswith(b':'), 'PING: token must be a trailing param')
    _need(_TOKEN.fullmatch(rest[1:]), 'PING: invalid token')


def _check_pong_command(rest):
    _need(rest.startswith(b':'), 'PONG: token must be a trailing param')
    _need(_TOKEN.fullmatch(rest[1:]), 'PONG: invalid token')


_COMMANDS = {
    b'NICK': _check_nick_command,
    b'USER': _check_user_command,
    b'JOIN': _check_join_command,
    b'PART': _check_part_command,
    b'PRIVMSG': _check_message_command,
    b'NOTICE': _check_message_command,
    b'PING': _check_ping_command,
    b'PONG': _check_pong_command,
}


def _check_numeric_reply(line):
    # ``:<server> <numeric> <nick> :<text>`` -- text may contain spaces, so
    # peel off the three fixed fields before the trailing param.
    body = line[1:]  # drop the leading ':'
    parts = body.split(b' ', 3)
    _need(len(parts) == 4, 'numeric: too few fields')
    server, numeric, nick, trailing = parts
    _need(_SERVER.fullmatch(server), 'numeric: invalid server prefix')
    _need(_NUMERIC.fullmatch(numeric), 'numeric: reply code is not 3 digits')
    _need(_NICK.fullmatch(nick), 'numeric: invalid target nickname')
    _need(trailing.startswith(b':'), 'numeric: text must be a trailing param')
    _need(_TEXT.fullmatch(trailing[1:]), 'numeric: invalid text')


def check(covertext):
    """Raise :class:`IrcRealismError` unless ``covertext`` is a valid IRC line."""
    if not isinstance(covertext, (bytes, bytearray)):
        raise IrcRealismError('covertext must be bytes')
    covertext = bytes(covertext)
    _need(covertext.endswith(b'\r\n'), 'line is not CRLF-terminated')
    line = covertext[:-2]
    _need(b'\r' not in line and b'\n' not in line,
          'embedded CR or LF outside the terminator')
    _need(line, 'empty line')

    if line.startswith(b':'):
        _check_numeric_reply(line)
        return

    command, sep, rest = line.partition(b' ')
    _need(sep, 'no space between command and parameters')
    handler = _COMMANDS.get(command)
    _need(handler is not None, 'unknown IRC command %r' % (command,))
    handler(rest)
