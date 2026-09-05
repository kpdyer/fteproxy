#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Canonical encoding for the public key carried in connection strings."""

import base64
import re

from fteproxy.handshake import KEY_BYTES

SERVER_ID_LENGTH = 43
_SERVER_ID = re.compile(r'^[A-Za-z0-9_-]{%d}$' % SERVER_ID_LENGTH)


def encode_server_id(public_bytes):
    """Encode one 32-byte public key as unpadded canonical base64url."""
    if not isinstance(public_bytes, (bytes, bytearray)):
        raise TypeError('server-id input must be bytes')
    public_bytes = bytes(public_bytes)
    if len(public_bytes) != KEY_BYTES:
        raise ValueError('server-id input must be %d bytes' % KEY_BYTES)
    return base64.urlsafe_b64encode(public_bytes).rstrip(b'=').decode('ascii')


def decode_server_id(text):
    """Decode a canonical unpadded base64url public key.

    ``base64.urlsafe_b64decode`` silently ignores non-alphabet characters and
    accepts non-zero padding bits. Both properties permit several strings to
    name the same key, undermining URI validation and secret redaction.
    """
    if not isinstance(text, str) or _SERVER_ID.fullmatch(text) is None:
        raise ValueError('server-id must be 43 unpadded base64url characters')
    try:
        raw = base64.b64decode(
            (text + '=').encode('ascii'), altchars=b'-_', validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError('server-id is not valid base64url') from exc
    if len(raw) != KEY_BYTES or encode_server_id(raw) != text:
        raise ValueError('server-id is not canonical base64url')
    return raw
