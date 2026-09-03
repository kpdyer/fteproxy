#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loading and validating the format definitions.

A definitions file maps a format name to the regex its covertexts are drawn
from and the fixed byte length of one covertext. Names come in pairs: a
``-request`` for client-to-server and a ``-response`` for server-to-client,
sharing a base name such as ``manual-http``. The base name is what a
connection string and a client hello carry; the two directions are derived
from it.
"""


import os
import json

import fteproxy.conf


class InvalidRegexName(Exception):
    pass


class DefinitionsError(Exception):
    """A definitions file that cannot be served as written."""


#: Every format must hold a client hello, which is about 55 bytes of fields
#: plus the record layer's 12-byte seal. 128 leaves room for a longer format
#: name and for a field a later protocol version adds, and is checked at load
#: so a format that cannot carry a handshake is caught here rather than as a
#: client that hangs.
MIN_CAPACITY = 128

_definitions = None
_checked_releases = set()

REQUEST_SUFFIX = '-request'
RESPONSE_SUFFIX = '-response'

# ------------------------------------------------------------------------- #
# Schema v2 vocabulary
#
# A v1 entry carried only ``regex`` and (optionally) ``length``. Schema v2 adds
# the OPTIONAL keys below; a v1 entry stays valid and every accessor returns the
# documented default for a key it does not carry, so old releases load unchanged.
# ------------------------------------------------------------------------- #

#: ``role`` values. ``line`` is a symmetric protocol (one line grammar in both directions) that does not
#: split into a request and a response direction.
ROLE_REQUEST = 'request'
ROLE_RESPONSE = 'response'
ROLE_LINE = 'line'
ROLES = (ROLE_REQUEST, ROLE_RESPONSE, ROLE_LINE)

#: ``mode_hint`` values: the record-layer mode a format is designed for. See
#: ``docs/format-authoring.md``. The client's ``--mode`` still overrides it.
MODE_HYBRID = 'hybrid'
MODE_FORMAT = 'format'
MODE_HINTS = (MODE_HYBRID, MODE_FORMAT)


def _release_path(release):
    """The path of a definitions release, searched in the package's ``defs``
    directory first and then in ``examples/defs`` (where the retired shape
    catalog lives as ``shapes-20260110``), so ``--defs shapes-20260110`` reaches
    it. Raises :class:`FileNotFoundError` if no candidate exists.
    """
    release = str(release)
    def_dir = fteproxy.conf.getValue('general.defs_dir')
    base_dir = fteproxy.conf.getValue('general.base_dir')
    candidates = [
        os.path.join(def_dir, release + '.json'),
        os.path.join(base_dir, 'examples', 'defs', release + '.json'),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    raise FileNotFoundError(
        'no definitions release %r (looked in %s)'
        % (release, ' and '.join(os.path.dirname(c) for c in candidates)))


def load_definitions():
    global _definitions

    if _definitions == None:
        release = fteproxy.conf.getValue('fteproxy.defs.release')
        def_abspath = _release_path(release)

        with open(def_abspath) as fh:
            _definitions = json.load(fh)

        if release not in _checked_releases:
            check_capacities(_definitions)
            _checked_releases.add(release)

    return _definitions


def check_capacities(definitions, minimum=MIN_CAPACITY):
    """Raise :class:`DefinitionsError` for any format too small for a hello.

    Building the cipher also proves the regex compiles and that libfte can
    drive it at the configured length, so this doubles as a load-time syntax
    check. It costs one DFA compile per format, which the cache in
    :func:`fteproxy._regex_format` then hands back to every connection.
    """
    import fteproxy  # deferred: fteproxy imports this module at import time

    too_small = []
    for name, spec in definitions.items():
        length = spec.get('length', fteproxy.conf.getValue(
            'fteproxy.default_length'))
        try:
            capacity = fteproxy._make_cipher(
                spec['regex'], length, b'\x00' * 32).max_plaintext_bytes
        except Exception as e:
            raise DefinitionsError('format %s is unusable at length %d: %s'
                                   % (name, length, e))
        if capacity < minimum:
            too_small.append((name, length, capacity))

    if too_small:
        raise DefinitionsError(
            'these formats cannot carry a handshake (need %d bytes of '
            'capacity): %s' % (minimum, ', '.join(
                '%s at length %d holds %d' % row for row in too_small)))


def base_names(definitions=None):
    """The set of base names that have both a request and a response format."""
    definitions = load_definitions() if definitions is None else definitions
    requests = {name[:-len(REQUEST_SUFFIX)] for name in definitions
                if name.endswith(REQUEST_SUFFIX)}
    responses = {name[:-len(RESPONSE_SUFFIX)] for name in definitions
                 if name.endswith(RESPONSE_SUFFIX)}
    return requests & responses


def base_name(format_name):
    """``manual-http-request`` -> ``manual-http``."""
    for suffix in (REQUEST_SUFFIX, RESPONSE_SUFFIX):
        if format_name.endswith(suffix):
            return format_name[:-len(suffix)]
    return format_name


def getRegex(format_name):
    definitions = load_definitions()
    try:
        regex = definitions[format_name]['regex']
    except KeyError:
        raise InvalidRegexName(format_name)

    return regex


def getLength(format_name):
    definitions = load_definitions()
    try:
        length = definitions[format_name]['length']
    except KeyError:
        length = fteproxy.conf.getValue('fteproxy.default_length')

    return length


# ------------------------------------------------------------------------- #
# Schema v2 accessors
#
# The ``spec_*`` helpers read one key out of a spec dict and apply the default,
# so a caller holding a spec that is not in the loaded release (a fragment, a
# synthetic entry under validation) does not have to go through the loader. The
# ``get_*`` accessors are the same reads keyed by format name against the loaded
# release.
# ------------------------------------------------------------------------- #

def _infer_role(format_name):
    if format_name.endswith(REQUEST_SUFFIX):
        return ROLE_REQUEST
    if format_name.endswith(RESPONSE_SUFFIX):
        return ROLE_RESPONSE
    return ROLE_LINE


def spec_length(spec):
    """The covertext length of a spec, defaulting to ``fteproxy.default_length``."""
    return spec.get('length', fteproxy.conf.getValue('fteproxy.default_length'))


def spec_min_length(spec):
    """Reserved for variable-length covertexts (phase F7); default ``None``."""
    return spec.get('min_length', None)


def spec_max_length(spec):
    """Reserved for variable-length covertexts (phase F7); default ``None``."""
    return spec.get('max_length', None)


def spec_port(spec):
    """The ports this format defaults on, as a list; default ``[]``."""
    return list(spec.get('port', []))


def spec_role(format_name, spec):
    """``request``/``response``/``line``; default inferred from the name suffix."""
    return spec.get('role', _infer_role(format_name))


def spec_mode_hint(spec):
    """The record-layer mode this format is designed for; default ``hybrid``."""
    return spec.get('mode_hint', MODE_HYBRID)


def spec_is_default(spec):
    """Whether this entry marks its base as the release default; default ``False``."""
    return bool(spec.get('default', False))


def spec_description(spec):
    """A human-readable description; default the empty string."""
    return spec.get('description', '')


def _spec(format_name):
    definitions = load_definitions()
    try:
        return definitions[format_name]
    except KeyError:
        raise InvalidRegexName(format_name)


def get_port(format_name):
    return spec_port(_spec(format_name))


def get_role(format_name):
    return spec_role(format_name, _spec(format_name))


def get_mode_hint(format_name):
    return spec_mode_hint(_spec(format_name))


def get_description(format_name):
    return spec_description(_spec(format_name))


def is_default(format_name):
    return spec_is_default(_spec(format_name))


def default_base(definitions=None):
    """The base name whose entries mark it the release default, else ``None``.

    A base counts as default when either of its direction entries carries
    ``"default": true``; the first such base in file order wins.
    """
    definitions = load_definitions() if definitions is None else definitions
    for name, spec in definitions.items():
        if spec_is_default(spec):
            return base_name(name)
    return None
