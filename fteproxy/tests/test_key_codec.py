#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Canonical server-id parsing shared by the URI and socket APIs."""

import pytest

import fteproxy
import fteproxy.config
import fteproxy.key_codec


PUBLIC = bytes(range(32))
SERVER_ID = fteproxy.key_codec.encode_server_id(PUBLIC)


def test_canonical_server_id_round_trips():
    assert len(SERVER_ID) == 43
    assert fteproxy.key_codec.decode_server_id(SERVER_ID) == PUBLIC
    assert fteproxy.config.decode_server_id(SERVER_ID) == PUBLIC
    assert fteproxy._as_key_bytes(SERVER_ID, 'server_id') == PUBLIC


def test_connection_string_is_exported_from_the_documented_api():
    assert fteproxy.ConnectionString is fteproxy.config.ConnectionString


@pytest.mark.parametrize('mutate', [
    lambda text: text + '!!!!',
    lambda text: text[:10] + '!!!!' + text[10:],
    lambda text: text[:-1] + '!',
    lambda text: text + '=',
])
def test_junk_and_padding_are_rejected(mutate):
    malformed = mutate(SERVER_ID)
    with pytest.raises(fteproxy.config.ConfigError):
        fteproxy.config.decode_server_id(malformed)
    with pytest.raises(ValueError):
        fteproxy._as_key_bytes(malformed, 'server_id')


def test_noncanonical_padding_bits_are_rejected():
    # Thirty-two zero bytes end in ``A``. ``B`` has the same four data bits
    # but non-zero padding bits, and permissive decoders map both to one key.
    canonical = fteproxy.key_codec.encode_server_id(bytes(32))
    assert canonical.endswith('A')
    with pytest.raises(ValueError):
        fteproxy.key_codec.decode_server_id(canonical[:-1] + 'B')


def test_malformed_connection_string_is_still_redacted(caplog):
    malformed = SERVER_ID[:10] + '!!!!' + SERVER_ID[10:]
    with caplog.at_level('INFO', logger='fteproxy'):
        fteproxy.info('checking fte://%s@example.test:8080' % malformed)
    assert malformed not in caplog.text
    assert 'fte://…@example.test:8080' in caplog.text
