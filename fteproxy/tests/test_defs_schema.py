#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the schema-v2 loader, the validator, and the realism harness (F0)."""

import re

import pytest

import fteproxy
import fteproxy.conf
import fteproxy.defs
import fteproxy.defs.validate as validate
import fteproxy.tests.realism as realism


#: A synthetic entry carrying every schema-v2 key with a non-default value.
_ALL_KEYS = {
    'regex': r'^GET /[a-zA-Z0-9]+ HTTP/1\.1\r\nHost: [a-z0-9.-]+\r\n\r\n$',
    'length': 512,
    'min_length': None,
    'max_length': None,
    'port': [80, 8080, 8000],
    'role': 'request',
    'mode_hint': 'hybrid',
    'default': True,
    'description': 'a synthetic all-keys entry',
}

#: An old-style (schema-v1) entry: only regex and length.
_OLD_ENTRY = {'regex': r'^[a-z]+$', 'length': 256}


@pytest.fixture(autouse=True)
def _release_20260110():
    previous = fteproxy.conf.getValue('fteproxy.defs.release')
    fteproxy.conf.setValue('fteproxy.defs.release', '20260110')
    fteproxy.defs._definitions = None
    yield
    fteproxy.conf.setValue('fteproxy.defs.release', previous)
    fteproxy.defs._definitions = None


class TestSchemaLoads:

    def test_the_shape_catalog_loads(self):
        definitions = fteproxy.defs.load_definitions()
        assert 'manual-http-request' in definitions
        assert 'manual-http' in fteproxy.defs.base_names(definitions)

    def test_a_synthetic_all_keys_entry_loads_and_validates(self):
        # An all-keys v2 entry passes the load-time capacity/compile check.
        fteproxy.defs.check_capacities({'synthetic-request': _ALL_KEYS})
        # and every schema-v2 accessor reads back what it carries.
        assert fteproxy.defs.spec_length(_ALL_KEYS) == 512
        assert fteproxy.defs.spec_port(_ALL_KEYS) == [80, 8080, 8000]
        assert fteproxy.defs.spec_role('synthetic-request', _ALL_KEYS) == 'request'
        assert fteproxy.defs.spec_mode_hint(_ALL_KEYS) == 'hybrid'
        assert fteproxy.defs.spec_is_default(_ALL_KEYS) is True
        assert fteproxy.defs.spec_description(_ALL_KEYS) == 'a synthetic all-keys entry'

    def test_default_base_finds_the_marked_base(self):
        synthetic = {'foo-request': _ALL_KEYS,
                     'foo-response': dict(_ALL_KEYS, role='response')}
        assert fteproxy.defs.default_base(synthetic) == 'foo'
        # No entry marked default -> None (as in the 20260110 catalog).
        assert fteproxy.defs.default_base({'bar-request': _OLD_ENTRY}) is None


class TestAccessorDefaults:
    """An old (regex+length only) entry gets the documented v2 defaults."""

    def test_spec_helpers_on_an_old_entry(self):
        assert fteproxy.defs.spec_min_length(_OLD_ENTRY) is None
        assert fteproxy.defs.spec_max_length(_OLD_ENTRY) is None
        assert fteproxy.defs.spec_port(_OLD_ENTRY) == []
        assert fteproxy.defs.spec_mode_hint(_OLD_ENTRY) == 'hybrid'
        assert fteproxy.defs.spec_is_default(_OLD_ENTRY) is False
        assert fteproxy.defs.spec_description(_OLD_ENTRY) == ''

    def test_role_is_inferred_from_the_suffix(self):
        assert fteproxy.defs.spec_role('x-request', _OLD_ENTRY) == 'request'
        assert fteproxy.defs.spec_role('x-response', _OLD_ENTRY) == 'response'
        assert fteproxy.defs.spec_role('x-line', _OLD_ENTRY) == 'line'

    def test_get_accessors_on_a_loaded_old_entry(self):
        # manual-http-request in 20260110 carries only regex.
        assert fteproxy.defs.get_role('manual-http-request') == 'request'
        assert fteproxy.defs.get_mode_hint('manual-http-request') == 'hybrid'
        assert fteproxy.defs.get_port('manual-http-request') == []
        assert fteproxy.defs.is_default('manual-http-request') is False
        assert fteproxy.defs.get_description('manual-http-request') == ''

    def test_an_unknown_name_raises(self):
        with pytest.raises(fteproxy.defs.InvalidRegexName):
            fteproxy.defs.get_role('no-such-format')


class TestValidate:

    def test_validate_release_passes_on_the_shape_catalog(self):
        summary = validate.validate_release('shapes-20260110', samples=8)
        assert summary  # non-empty
        names = {name for name, _l, _c, _m in summary}
        assert 'manual-http-request' in names
        for _name, _length, capacity, _mode in summary:
            assert capacity >= fteproxy.defs.MIN_CAPACITY

    def test_a_too_small_format_fails(self):
        with pytest.raises(validate.FormatValidationError) as excinfo:
            validate.validate_format('tiny-request',
                                     {'regex': r'^[01]+$', 'length': 300})
        assert 'tiny-request' in str(excinfo.value)

    def test_an_all_keys_entry_validates(self):
        name, length, capacity, mode_hint = validate.validate_format(
            'synthetic-request', _ALL_KEYS, samples=8)
        assert name == 'synthetic-request'
        assert length == 512
        assert capacity >= fteproxy.defs.MIN_CAPACITY
        assert mode_hint == 'hybrid'


class TestRealismHarness:

    def test_statistical_guard_rejects_a_single_char_run(self):
        with pytest.raises(realism.RealismError):
            realism.statistical_guard([b'a' * 256])

    def test_statistical_guard_accepts_a_varied_covertext(self):
        varied = bytes(i % 251 for i in range(256))
        # Should not raise.
        realism.statistical_guard([varied])

    def test_format_covertexts_for_manual_http_request_all_match(self):
        regex = fteproxy.defs.getRegex('manual-http-request')
        length = fteproxy.defs.getLength('manual-http-request')
        covertexts = realism.format_covertexts(regex, length, n=32)
        assert len(covertexts) == 32
        pattern = re.compile(regex.encode('latin-1'), re.DOTALL)
        for covertext in covertexts:
            assert len(covertext) == length
            assert pattern.fullmatch(covertext)

    def test_self_test_passes(self):
        assert realism.self_test()
