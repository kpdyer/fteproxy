#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Load release-scoped regex definitions and expose schema defaults.

Tunnel formats are request/response pairs sharing a base name. Entries declare
fixed or variable wire lengths; framing is fixed, terminator, or length-prefix.
The external length prefix is not part of the regex. See docs/format-authoring.md
for capacity rules, metadata, assembly, and validation.
"""


import os
import json
import re
import threading

import fteproxy.conf


class InvalidRegexName(Exception):
    pass


class DefinitionsError(Exception):
    """A definitions file that cannot be served as written."""


# Minimum cipher capacity at the handshake length. A sealed client hello
# needs 55 + len(base_name) bytes; unusually long names may require more.
MIN_CAPACITY = 128

# Definitions are cached by release rather than as one process-wide value. A
# caller may therefore use two releases concurrently, and changing the
# configured default never needs a private cache reset.
_definition_cache = {}
_definition_lock = threading.RLock()

REQUEST_SUFFIX = '-request'
RESPONSE_SUFFIX = '-response'

# ------------------------------------------------------------------------- #
# Schema v2 vocabulary
#
# A v1 entry carried only ``regex`` and (optionally) ``length``. Schema v2 adds
# the OPTIONAL keys below; a v1 entry stays valid and every accessor returns the
# documented default for a key it does not carry, so old releases load unchanged.
# ------------------------------------------------------------------------- #

# Role metadata. Even a symmetric line grammar needs request/response entries.
ROLE_REQUEST = 'request'
ROLE_RESPONSE = 'response'
ROLE_LINE = 'line'
ROLES = (ROLE_REQUEST, ROLE_RESPONSE, ROLE_LINE)

#: ``mode_hint`` values: the record-layer mode a format is designed for. See
#: ``docs/format-authoring.md``. The client's ``--mode`` still overrides it.
MODE_HYBRID = 'hybrid'
MODE_FORMAT = 'format'
MODE_HINTS = (MODE_HYBRID, MODE_FORMAT)

#: How the authenticated ciphertext after a hybrid covertext header is framed.
#:
#: ``raw`` preserves the original FTE hybrid layout: the encrypted body follows
#: the header directly.  ``http-chunked`` makes that same encrypted body one
#: complete HTTP/1.1 chunked message body.  It is paired with ``hybrid_regex``
#: in a definition so the post-handshake header advertises
#: ``Transfer-Encoding: chunked`` while the handshake can keep using the base
#: regex as a complete, zero-body HTTP message.
HYBRID_FRAMING_RAW = 'raw'
HYBRID_FRAMING_HTTP_CHUNKED = 'http-chunked'
HYBRID_FRAMINGS = (HYBRID_FRAMING_RAW, HYBRID_FRAMING_HTTP_CHUNKED)

# A release is a catalog identifier, never a path. Date releases and named
# historical/example catalogs such as ``shapes-20260110`` both fit this form.
MAX_RELEASE_ID_LENGTH = 64
_RELEASE_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')

# Historical name retained without carrying a byte-identical second catalog.
_RELEASE_ALIASES = {'shapes-20260110': '20260110'}

# Maximum number of evenly spaced wire lengths for a variable format.
# Each length needs compiled ranking tables; a small set bounds that cost.
# Length selection depends on queued payload and is not a privacy guarantee.
LENGTH_STEPS = 8

# Wire framing: fixed length, a unique suffix, or an external length prefix.
# Fixed-length formats may use fixed or length-prefix framing. Terminators
# require a range and must occur only at the end of each covertext.
FRAMING_FIXED = 'fixed'
FRAMING_TERMINATOR = 'terminator'
FRAMING_LENGTH_PREFIX = 'length-prefix'
FRAMINGS = (FRAMING_FIXED, FRAMING_TERMINATOR, FRAMING_LENGTH_PREFIX)

#: Width of a ``length-prefix`` format's framing header, in bytes. Two, because
#: RFC 1035 section 4.2.2 says two; a covertext of ``W`` wire bytes is a message
#: of ``W - 2`` bytes behind a prefix carrying that number.
LENGTH_PREFIX_BYTES = 2


def validate_release_id(release):
    """Return a safe definitions-catalog identifier, or raise.

    Keeping this check next to the path construction protects non-CLI callers
    too; parser validation alone would still leave ``load_definitions`` open
    to path traversal.
    """
    release = str(release)
    if _RELEASE_ID.fullmatch(release) is None:
        raise DefinitionsError(
            'definitions release must be 1-%d letters, digits, "_" or "-", '
            'starting with a letter or digit' % MAX_RELEASE_ID_LENGTH)
    return release


def _canonical_release(release):
    """Validate a release identifier and resolve its compatibility alias."""
    release = validate_release_id(release)
    return _RELEASE_ALIASES.get(release, release)


def _release_path(release):
    """Return the packaged path for a definitions release or legacy alias."""
    release = _canonical_release(release)
    def_dir = fteproxy.conf.getValue('general.defs_dir')
    path = os.path.join(def_dir, release + '.json')
    if os.path.exists(path):
        return path
    raise FileNotFoundError(
        'no definitions release %r in %s' % (release, def_dir))


def load_definitions(release=None):
    """Load and validate one definitions release.

    ``release`` defaults to ``fteproxy.defs.release`` for compatibility with
    the original API.  The cache is keyed by the normalized release name, so
    selecting another release cannot return the catalog that happened to load
    first.  Callers that represent a connection should pass the release
    explicitly and retain the returned mapping for the life of that
    connection.
    """
    if release is None:
        release = fteproxy.conf.getValue('fteproxy.defs.release')
    release = _canonical_release(release)

    with _definition_lock:
        definitions = _definition_cache.get(release)
        if definitions is None:
            with open(_release_path(release)) as fh:
                definitions = json.load(fh)
            check_capacities(definitions)
            _definition_cache[release] = definitions
        return definitions


def clear_cache(release=None):
    """Discard cached definitions, normally only for tests or live tooling.

    Switching releases does not require this: :func:`load_definitions` keeps a
    distinct entry for every release.  With no argument all entries are
    removed; otherwise only the named release is removed.
    """
    with _definition_lock:
        if release is None:
            _definition_cache.clear()
        else:
            release = _canonical_release(release)
            _definition_cache.pop(release, None)


def _catalog(definitions=None):
    """Return a definitions mapping from a mapping, release, or the default."""
    if definitions is None:
        return load_definitions()
    if isinstance(definitions, (str, int)):
        return load_definitions(definitions)
    return definitions


def check_capacities(definitions, minimum=MIN_CAPACITY):
    """Validate framing declarations and the handshake capacity of each base regex.

    The floor applies at spec_length (max_length for variable formats). This pass
    does not prove terminator uniqueness or test every shorter length and hybrid
    regex; use defs-check for those checks.
    """
    import fteproxy  # deferred: fteproxy imports this module at import time

    too_small = []
    for name, spec in definitions.items():
        _check_variable_keys(name, spec)
        length = spec_length(spec)
        try:
            capacity = fteproxy._spec_cipher(
                spec, length, b'\x00' * 32).max_plaintext_bytes
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


def _check_variable_keys(name, spec):
    """Reject conflicting or incomplete length, delimiter, and hybrid declarations.

    Ranges require both endpoints and a terminator or length prefix. Fixed formats
    may also carry a length prefix. Terminators require a range.
    """
    low, high = spec_min_length(spec), spec_max_length(spec)
    terminator = spec_terminator(spec)
    framing = spec.get('framing', None)
    hybrid_framing = spec_hybrid_framing(spec)
    if hybrid_framing not in HYBRID_FRAMINGS:
        raise DefinitionsError(
            'format %s declares hybrid_framing %r, which is not one of %r'
            % (name, hybrid_framing, HYBRID_FRAMINGS))
    hybrid_regex = spec.get('hybrid_regex', None)
    if hybrid_regex is not None and not isinstance(hybrid_regex, str):
        raise DefinitionsError('format %s declares a non-string hybrid_regex'
                               % name)
    if hybrid_framing == HYBRID_FRAMING_HTTP_CHUNKED:
        if hybrid_regex is None:
            raise DefinitionsError(
                'format %s uses http-chunked hybrid framing without a '
                'hybrid_regex' % name)
        if 'Transfer-Encoding: chunked\r\n' not in hybrid_regex:
            raise DefinitionsError(
                'format %s uses http-chunked hybrid framing but its '
                'hybrid_regex does not advertise Transfer-Encoding: chunked'
                % name)
    if framing is not None and framing not in FRAMINGS:
        raise DefinitionsError(
            'format %s declares framing %r, which is not one of %r'
            % (name, framing, FRAMINGS))
    if framing == FRAMING_LENGTH_PREFIX and terminator is not None:
        raise DefinitionsError(
            'format %s declares both a terminator and length-prefix framing; a '
            'covertext is delimited one way or the other' % name)
    if framing == FRAMING_TERMINATOR and terminator is None:
        raise DefinitionsError(
            'format %s declares terminator framing without a terminator' % name)
    if framing == FRAMING_FIXED and terminator is not None:
        raise DefinitionsError(
            'format %s declares fixed framing with a terminator' % name)
    if framing == FRAMING_FIXED and (low is not None or high is not None):
        raise DefinitionsError(
            'format %s declares fixed framing with a variable length range'
            % name)
    if framing == FRAMING_TERMINATOR and low is None and high is None:
        raise DefinitionsError(
            'format %s declares terminator framing for a fixed-length format'
            % name)
    if low is None and high is None and terminator is None:
        return                      # fixed length, however it is framed
    delimiter = (framing if framing == FRAMING_LENGTH_PREFIX else terminator)
    declared = [key for key, value in
                (('min_length', low), ('max_length', high),
                 ('a delimiter', delimiter)) if value is not None]
    if len(declared) != 3:
        raise DefinitionsError(
            'format %s declares %s: a variable-length format needs all of '
            'min_length, max_length and either a terminator or '
            '"framing": "length-prefix"' % (name, ', '.join(declared)))
    if 'length' in spec:
        raise DefinitionsError(
            'format %s carries both length and min_length/max_length; a format '
            'is either fixed or variable' % name)
    if low > high:
        raise DefinitionsError(
            'format %s has min_length %d above max_length %d' % (name, low, high))
    if delimiter == FRAMING_LENGTH_PREFIX and low <= LENGTH_PREFIX_BYTES:
        raise DefinitionsError(
            'format %s has min_length %d, which leaves no message behind its '
            '%d-byte length prefix' % (name, low, LENGTH_PREFIX_BYTES))


def base_names(definitions=None):
    """The set of base names that have both a request and a response format."""
    definitions = _catalog(definitions)
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


def getRegex(format_name, definitions=None):
    definitions = _catalog(definitions)
    try:
        regex = definitions[format_name]['regex']
    except KeyError:
        raise InvalidRegexName(format_name)

    return regex


def getLength(format_name, definitions=None):
    """Return the handshake wire length, or the default length for an unknown name."""
    definitions = _catalog(definitions)
    try:
        spec = definitions[format_name]
    except KeyError:
        return fteproxy.conf.getValue('fteproxy.default_length')

    return spec_length(spec)


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
    """Return fixed length or max_length, including any external prefix.

    Handshakes use this length; hybrid headers use hybrid_header_length instead.
    """
    maximum = spec_max_length(spec)
    if maximum is not None:
        return maximum
    return spec.get('length', fteproxy.conf.getValue('fteproxy.default_length'))


def spec_min_length(spec):
    """The shortest covertext a variable-length format emits; ``None`` if fixed."""
    return spec.get('min_length', None)


def spec_max_length(spec):
    """The longest covertext a variable-length format emits; ``None`` if fixed."""
    return spec.get('max_length', None)


def spec_terminator(spec):
    """Return the declared terminator as bytes, or None when absent.

    Length-prefixed formats, including variable ones, have no terminator.
    """
    terminator = spec.get('terminator', None)
    if terminator is None:
        return None
    if isinstance(terminator, str):
        return terminator.encode('latin-1')
    return bytes(terminator)


def spec_framing(spec):
    """Return explicit framing, or infer terminator/fixed from the declaration."""
    framing = spec.get('framing', None)
    if framing is not None:
        return framing
    if spec_terminator(spec) is not None:
        return FRAMING_TERMINATOR
    return FRAMING_FIXED


def spec_is_variable(spec):
    """Whether both range endpoints and non-fixed framing are declared.

    Equal endpoints are allowed and yield one actual length. Schema validation
    rejects incomplete or conflicting declarations.
    """
    return (spec_min_length(spec) is not None
            and spec_max_length(spec) is not None
            and spec_framing(spec) != FRAMING_FIXED)


def spec_allowed_lengths(spec):
    """Return sorted wire lengths: one fixed value or up to LENGTH_STEPS range points.

    Include both endpoints and derive the same set on both peers.
    """
    low, high = spec_min_length(spec), spec_max_length(spec)
    if low is None or high is None:
        return (spec_length(spec),)
    steps = max(2, min(LENGTH_STEPS, high - low + 1))
    return tuple(sorted({round(low + i * (high - low) / (steps - 1))
                         for i in range(steps)}))


def spec_port(spec):
    """The ports this format defaults on, as a list; default ``[]``."""
    return list(spec.get('port', []))


def spec_role(format_name, spec):
    """``request``/``response``/``line``; default inferred from the name suffix."""
    return spec.get('role', _infer_role(format_name))


def spec_mode_hint(spec):
    """The record-layer mode this format is designed for; default ``hybrid``."""
    return spec.get('mode_hint', MODE_HYBRID)


def spec_hybrid_regex(spec):
    """The covertext regex for post-handshake hybrid headers.

    Most formats use their ordinary ``regex``.  HTTP needs a distinct header
    grammar: handshakes are complete zero-body messages, while data records
    advertise the chunked body that follows their covertext header.
    """
    return spec.get('hybrid_regex', spec['regex'])


def spec_hybrid_framing(spec):
    """How a hybrid ciphertext body is framed after its covertext header."""
    return spec.get('hybrid_framing', HYBRID_FRAMING_RAW)


def spec_is_default(spec):
    """Whether this entry marks its base as the release default; default ``False``."""
    return bool(spec.get('default', False))


def spec_description(spec):
    """A human-readable description; default the empty string."""
    return spec.get('description', '')


def _spec(format_name, definitions=None):
    definitions = _catalog(definitions)
    try:
        return definitions[format_name]
    except KeyError:
        raise InvalidRegexName(format_name)


def get_port(format_name):
    return spec_port(_spec(format_name))


def get_terminator(format_name):
    """The covertext terminator of a loaded format, or ``None`` if fixed."""
    return spec_terminator(_spec(format_name))


def get_framing(format_name):
    """How a loaded format's covertexts are delimited; one of :data:`FRAMINGS`."""
    return spec_framing(_spec(format_name))


def get_allowed_lengths(format_name):
    """The covertext lengths a loaded format may emit, ascending."""
    return spec_allowed_lengths(_spec(format_name))


def is_variable(format_name):
    """Whether a loaded format emits covertexts of more than one length."""
    return spec_is_variable(_spec(format_name))


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
    definitions = _catalog(definitions)
    for name, spec in definitions.items():
        if spec_is_default(spec):
            return base_name(name)
    return None
