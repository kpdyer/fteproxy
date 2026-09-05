#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Keep the shipped 20260903 catalog equal to the union of its protocol parts.

Assert five request/response pairs, HTTP as the only default, and successful
release validation. Update the assembled catalog whenever a fragment changes.
"""

import glob
import json
import os

import pytest

import fteproxy
import fteproxy.conf
import fteproxy.defs
import fteproxy.defs.validate as validate


RELEASE = '20260903'

DEFS_DIR = os.path.dirname(os.path.abspath(fteproxy.defs.__file__))
PARTS_DIR = os.path.join(DEFS_DIR, 'parts')
RELEASE_PATH = os.path.join(DEFS_DIR, RELEASE + '.json')

PROTOCOLS = {'http', 'ftp', 'smtp', 'sip', 'dns'}


def _load(path):
    with open(path) as handle:
        return json.load(handle)


def _parts():
    """Every fragment, merged. Fails on a name two fragments both claim."""
    merged = {}
    paths = sorted(glob.glob(os.path.join(PARTS_DIR, '*.json')))
    assert paths, 'no fragments under %s' % PARTS_DIR
    for path in paths:
        for name, spec in _load(path).items():
            assert name not in merged, \
                '%s is defined by two fragments' % name
            merged[name] = spec
    return merged


class TestAssembly:
    """The release file is exactly the union of the fragments."""

    def test_the_release_is_the_merge_of_every_fragment(self):
        assert _load(RELEASE_PATH) == _parts()

    def test_every_protocol_ships_a_fragment(self):
        names = {os.path.splitext(os.path.basename(path))[0]
                 for path in glob.glob(os.path.join(PARTS_DIR, '*.json'))}
        assert names == PROTOCOLS

    def test_the_release_has_ten_entries(self):
        """Five protocols, a request and a response each."""
        assert len(_load(RELEASE_PATH)) == 2 * len(PROTOCOLS)


class TestReleaseValidates:

    def test_validate_release_passes(self):
        """Every entry builds, clears the capacity floor, round-trips the
        record layer, and matches its regex in format mode."""
        summary = validate.validate_release(RELEASE, samples=8)
        assert {name for name, _l, _c, _m in summary} == \
            {'%s-%s' % (proto, direction)
             for proto in PROTOCOLS for direction in ('request', 'response')}
        for name, _length, capacity, _mode in summary:
            assert capacity >= fteproxy.defs.MIN_CAPACITY, name


class TestReleaseContents:

    @pytest.fixture
    def definitions(self):
        return _load(RELEASE_PATH)

    def test_base_names_are_the_five_protocols(self, definitions):
        assert fteproxy.defs.base_names(definitions) == PROTOCOLS

    def test_http_is_the_only_default(self, definitions):
        marked = {name for name, spec in definitions.items()
                  if fteproxy.defs.spec_is_default(spec)}
        assert marked == {'http-request', 'http-response'}
        for name, spec in definitions.items():
            expected = name.startswith('http-')
            assert fteproxy.defs.spec_is_default(spec) is expected, name
        assert fteproxy.defs.default_base(definitions) == 'http'

    def test_every_entry_names_the_ports_it_defaults_on(self, definitions):
        for name, spec in definitions.items():
            assert fteproxy.defs.spec_port(spec), name

    def test_the_release_is_the_shipped_default(self):
        """The configured default catalog is 20260903."""
        assert fteproxy.conf.getValue('fteproxy.defs.release') == RELEASE
