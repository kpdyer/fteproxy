#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate that a format definition is actually usable as written.

Loading a release (:func:`fteproxy.defs.check_capacities`) already proves every
regex compiles and holds a handshake. This module goes further and exercises a
format the way a live connection does, so a definition that compiles but cannot
carry traffic is caught before it ships:

* build the libfte cipher and require ``max_plaintext_bytes >=`` the capacity
  floor (:data:`fteproxy.defs.MIN_CAPACITY`);
* round-trip a batch of random payloads through
  :class:`fteproxy.record_layer.Encoder`/:class:`~fteproxy.record_layer.Decoder`
  in the format's ``mode_hint`` -- and in *both* modes when the hint is
  ``hybrid``, since the client's ``--mode`` may override it either way;
* assert every sealed **format-mode** covertext fully matches the regex, so the
  bytes on the wire really are drawn from the format's language.

The covertexts checked here come out of the record layer's sealing path (see the
seal-padding note in ``docs/format-authoring.md``), never a bare
``fte.FTE.encrypt`` of a short message, so a variable field is filled to capacity
with random format bytes exactly as it is in production.

:func:`validate_release` validates every format in a named release,
:func:`validate_fragment` validates a ``parts/<proto>.json`` fragment in
isolation, and :func:`validate_format` validates one entry. Each raises
:class:`FormatValidationError` naming the offending format(s); a pass returns a
summary list of ``(name, length, capacity, mode_hint)`` tuples.
"""

import json
import os
import re

import fteproxy.conf
import fteproxy.defs


class FormatValidationError(Exception):
    """A format definition that compiles but cannot carry traffic as written."""


#: Number of random payloads round-tripped per mode. The plan's floor is 32.
_SAMPLES = 32

_KEY = b'\x00' * 32


def _compiled_regex(regex):
    """The regex as a byte pattern.

    The dialect keeps every character ``<= U+00FF``, so ``latin-1`` is the exact
    byte encoding. ``DOTALL`` because a covertext field spelled ``.`` in the
    regex is drawn from the whole byte range by libfte, including newlines, and
    the check only asks whether the bytes lie in the format's language.
    """
    return re.compile(regex.encode('latin-1'), re.DOTALL)


def _modes_for(mode_hint):
    """Which record-layer modes to exercise for a given ``mode_hint``.

    ``format`` is always exercised (it is where the regex is checked); a
    ``hybrid`` format is exercised in both modes because either end's ``--mode``
    can select the other one.
    """
    if mode_hint == fteproxy.defs.MODE_HYBRID:
        return (fteproxy.defs.MODE_FORMAT, fteproxy.defs.MODE_HYBRID)
    return (fteproxy.defs.MODE_FORMAT,)


def validate_format(name, spec, samples=_SAMPLES):
    """Validate one format entry. Returns ``(name, length, capacity, mode_hint)``.

    Raises :class:`FormatValidationError` naming ``name`` on any failure.
    """
    import fteproxy  # deferred: fteproxy imports fteproxy.defs at import time
    import fteproxy.record_layer as rl

    if 'regex' not in spec:
        raise FormatValidationError('%s: no regex' % name)
    regex = spec['regex']
    length = fteproxy.defs.spec_length(spec)
    mode_hint = fteproxy.defs.spec_mode_hint(spec)
    if mode_hint not in fteproxy.defs.MODE_HINTS:
        raise FormatValidationError(
            '%s: mode_hint %r is not one of %r'
            % (name, mode_hint, fteproxy.defs.MODE_HINTS))
    role = fteproxy.defs.spec_role(name, spec)
    if role not in fteproxy.defs.ROLES:
        raise FormatValidationError(
            '%s: role %r is not one of %r' % (name, role, fteproxy.defs.ROLES))

    try:
        capacity = fteproxy._make_cipher(regex, length, _KEY).max_plaintext_bytes
    except Exception as e:
        raise FormatValidationError(
            '%s: unusable at length %d: %s' % (name, length, e))
    if capacity < fteproxy.defs.MIN_CAPACITY:
        raise FormatValidationError(
            '%s: capacity %d bytes at length %d is below the %d-byte floor'
            % (name, capacity, length, fteproxy.defs.MIN_CAPACITY))

    pattern = _compiled_regex(regex)
    for mode in _modes_for(mode_hint):
        hybrid = (mode == fteproxy.defs.MODE_HYBRID)
        encoder = rl.Encoder(
            cipher=fteproxy._make_cipher(regex, length, _KEY),
            body_cipher=fteproxy._make_body_cipher(_KEY) if hybrid else None)
        decoder = rl.Decoder(
            cipher=fteproxy._make_cipher(regex, length, _KEY),
            body_cipher=fteproxy._make_body_cipher(_KEY) if hybrid else None)
        for i in range(samples):
            payload = os.urandom((i * 7) % (encoder.capacity + 1))
            encoder.push(payload)
            wire = encoder.pop()
            if not hybrid:
                for offset in range(0, len(wire), length):
                    covertext = wire[offset:offset + length]
                    if not pattern.fullmatch(covertext):
                        raise FormatValidationError(
                            '%s: a sealed format-mode covertext does not match '
                            'the regex' % name)
            decoder.push(wire)
            got = decoder.pop()
            if got != payload:
                raise FormatValidationError(
                    '%s: payload did not round-trip in %s mode' % (name, mode))
    return (name, length, capacity, mode_hint)


def _validate_definitions(definitions, source, samples=_SAMPLES):
    if not isinstance(definitions, dict):
        raise FormatValidationError('%s: not a JSON object of formats' % source)
    summary = []
    failures = []
    for name in sorted(definitions):
        try:
            summary.append(validate_format(name, definitions[name], samples))
        except FormatValidationError as e:
            failures.append(str(e))
    if failures:
        raise FormatValidationError(
            '%s: %d format(s) failed validation:\n  %s'
            % (source, len(failures), '\n  '.join(failures)))
    return summary


def validate_release(release, samples=_SAMPLES):
    """Validate every format in a named release. Returns the summary list.

    Loads the release file directly (searching the package ``defs`` directory
    and ``examples/defs``), so it does not disturb the process-wide loader
    state. Raises :class:`FileNotFoundError` for an unknown release and
    :class:`FormatValidationError` naming any offending formats.
    """
    path = fteproxy.defs._release_path(release)
    with open(path) as fh:
        definitions = json.load(fh)
    return _validate_definitions(definitions, source='release %s' % release,
                                 samples=samples)


def validate_fragment(path, samples=_SAMPLES):
    """Validate a ``parts/<proto>.json`` fragment in isolation.

    A fragment is the disjoint set of entries one protocol phase (F1-F5) writes
    before F6 assembles them, so it is validated as its own object of formats.
    """
    with open(path) as fh:
        definitions = json.load(fh)
    return _validate_definitions(definitions,
                                 source=os.path.basename(path), samples=samples)
