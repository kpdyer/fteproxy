#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loading and validating the format definitions.

A definitions file maps a format name to the regex its covertexts are drawn
from and the byte length of one covertext. Names come in pairs: a
``-request`` for client-to-server and a ``-response`` for server-to-client,
sharing a base name such as ``manual-http``. The base name is what a
connection string and a client hello carry; the two directions are derived
from it.

A format is either **fixed length** (``length``: every covertext is exactly
that many bytes) or **variable length** (``min_length``/``max_length`` plus a
``terminator``: each record picks one of a small set of allowed lengths and the
decoder frames the wire on the terminator). :func:`spec_allowed_lengths` is the
single definition of that set, so the two ends of a connection agree on it
without negotiating it. See ``docs/format-authoring.md``.
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

#: How many covertext lengths a variable-length format may emit.
#:
#: The set is small and evenly spaced on purpose. A format-mode record picks one
#: of these lengths and seals at it with a *fixed-length* cipher, so each allowed
#: length costs one compiled DFA in :func:`fteproxy._regex_format`: a continuous
#: range would cost one per byte. Small also keeps the decoder's "is this a
#: length we emit?" test tight, which is what fails a wrong-length frame closed.
#: Eight points span a protocol's plausible message sizes finely enough that a
#: length histogram is a spread rather than a spike, which is the whole point of
#: the exercise. It is *not* a security parameter: nothing secret is carried by
#: the choice, and the record's contents are sealed either way.
LENGTH_STEPS = 8


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

    The floor applies at :func:`spec_length` -- ``max_length`` for a
    variable-length format -- because that is the length the handshake seals at.
    A shorter allowed length only has to carry one data record, which
    ``fteproxy.defs.validate`` checks; the cheap load-time pass does not compile
    every allowed length.
    """
    import fteproxy  # deferred: fteproxy imports this module at import time

    too_small = []
    for name, spec in definitions.items():
        _check_variable_keys(name, spec)
        length = spec_length(spec)
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


def _check_variable_keys(name, spec):
    """Raise :class:`DefinitionsError` on an incoherent length declaration.

    A half-written variable-length entry is the dangerous case: a range with no
    terminator has nothing to frame on, and a terminator with no range would be
    ignored, so either would load as a fixed-length format and quietly emit one
    length again. Caught here, at load, rather than as a fingerprint nobody
    notices.
    """
    low, high = spec_min_length(spec), spec_max_length(spec)
    terminator = spec_terminator(spec)
    declared = [key for key, value in
                (('min_length', low), ('max_length', high),
                 ('terminator', terminator)) if value is not None]
    if not declared:
        return
    if len(declared) != 3:
        raise DefinitionsError(
            'format %s declares %s: a variable-length format needs all of '
            'min_length, max_length and terminator' % (name, ', '.join(declared)))
    if 'length' in spec:
        raise DefinitionsError(
            'format %s carries both length and min_length/max_length; a format '
            'is either fixed or variable' % name)
    if low > high:
        raise DefinitionsError(
            'format %s has min_length %d above max_length %d' % (name, low, high))


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
    """The fixed-frame covertext length of a format.

    For a variable-length format this is its ``max_length``: see
    :func:`spec_length` for why the fixed-frame paths (the handshake, the
    first-record scan, a hybrid header) all use the longest covertext.
    """
    definitions = load_definitions()
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
    """The covertext length a *single* fixed-length cipher is built at.

    For a fixed-length format that is its ``length`` (or the configured
    default). For a variable-length one it is ``max_length``: the handshake, the
    server's first-record scan and a hybrid-mode header are all fixed-length
    frames, and they use the longest covertext the format emits so that one
    frame size serves every format. Only post-handshake *format*-mode data
    records vary (see :func:`spec_allowed_lengths`).
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
    """The byte string every covertext of a variable-length format ends with.

    It is what the decoder frames on, so the format's regex must be unable to
    produce it anywhere but as that final suffix -- checked by
    ``fteproxy.defs.validate``. ``None`` for a fixed-length format, which is
    framed by its length instead. Returned as ``bytes``; the JSON carries it as
    a string (``"\\r\\n"``).
    """
    terminator = spec.get('terminator', None)
    if terminator is None:
        return None
    if isinstance(terminator, str):
        return terminator.encode('latin-1')
    return bytes(terminator)


def spec_is_variable(spec):
    """Whether this format emits covertexts of more than one length.

    True only when all three of ``min_length``, ``max_length`` and
    ``terminator`` are present: a length range with nothing to frame on could
    not be decoded, so a partial declaration is not a variable format (and
    :func:`fteproxy.defs.validate.validate_format` rejects it outright).
    """
    return (spec_min_length(spec) is not None
            and spec_max_length(spec) is not None
            and spec_terminator(spec) is not None)


def spec_allowed_lengths(spec):
    """The covertext lengths this format may emit, ascending.

    One length for a fixed-length format; for a variable-length one,
    :data:`LENGTH_STEPS` points spread evenly across
    ``[min_length, max_length]`` and including both ends. Both ends of a
    connection derive the set from the same definitions entry, so the sender
    picks a length out of it and the receiver checks a frame's length against
    it without either being negotiated.

    Deliberately *not* a continuous range: see :data:`LENGTH_STEPS`, and
    ``docs/format-authoring.md`` for why the length is chosen per record rather
    than left to libfte's ranking over a ``min_length``/``max_length`` format.
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


def get_terminator(format_name):
    """The covertext terminator of a loaded format, or ``None`` if fixed."""
    return spec_terminator(_spec(format_name))


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
    definitions = load_definitions() if definitions is None else definitions
    for name, spec in definitions.items():
        if spec_is_default(spec):
            return base_name(name)
    return None
