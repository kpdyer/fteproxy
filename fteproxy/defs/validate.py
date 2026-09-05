#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate definitions beyond the loader's maximum-length capacity check.

Build every allowed base cipher, require data capacity, prove terminator
uniqueness, and find a capable hybrid-header length. Round-trip sampled payloads
in format mode, and also hybrid when mode_hint is hybrid. Check emitted framing
and regex membership; protocol-specific realism parsers run separately in tests.

validate_format returns one (name, length, capacity, mode_hint) tuple.
validate_release and validate_fragment return lists of those tuples or raise
FormatValidationError with per-format failures.
"""

from collections import deque
import json
import os
import re

import regex2dfa

import fteproxy.conf
import fteproxy.defs


class FormatValidationError(Exception):
    """A malformed or unusable format definition."""


# Random payload samples per mode, in addition to structural validation.
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


# --------------------------------------------------------------------------- #
# Terminator uniqueness
#
# A variable-length format is framed by reading up to its terminator, so if the
# format's language could produce that byte string anywhere else in a covertext,
# the decoder would cut a record in half -- and, since the halves do not unseal,
# fail the connection closed on traffic that was perfectly valid. The property
# has to hold for the *language*, not merely for the covertexts anyone happened
# to sample, so it is checked from the pattern, and the sampled check below is a
# second opinion rather than the proof.
# --------------------------------------------------------------------------- #

def _kmp_failure(pattern):
    """Return KMP fallback lengths for the non-empty byte ``pattern``."""
    failure = [0] * len(pattern)
    matched = 0
    for index in range(1, len(pattern)):
        while matched and pattern[index] != pattern[matched]:
            matched = failure[matched - 1]
        if pattern[index] == pattern[matched]:
            matched += 1
        failure[index] = matched
    return failure


def _advance_match(pattern, failure, matched, byte):
    """Advance a KMP prefix length, retaining a full match until one byte on."""
    if matched == len(pattern):
        matched = failure[-1]
    while matched and byte != pattern[matched]:
        matched = failure[matched - 1]
    if byte == pattern[matched]:
        matched += 1
    return matched


def _accepted_witness(parents, state):
    """Reconstruct the shortest byte string reaching a product ``state``."""
    witness = bytearray()
    while parents[state] is not None:
        state, byte = parents[state]
        witness.append(byte)
    witness.reverse()
    return bytes(witness)


def check_terminator_uniqueness(name, regex, terminator):
    """Prove every accepted covertext has one terminator, at its exact end.

    The proof traverses the product of the regex's minimized DFA and a KMP
    matcher for ``terminator``. The latter records both the longest terminator
    prefix at the current suffix and whether a completed match has since been
    followed by another byte. The product is finite, so visiting every reachable
    product state proves the property for the whole language, including loops
    and overlapping terminators.

    Raises :class:`FormatValidationError` naming ``name`` and a shortest unsafe
    witness when the property does not hold.
    """
    if not terminator:
        raise FormatValidationError('%s: the terminator is empty' % name)
    try:
        dfa = regex2dfa.Regex2DFA(regex).minimized_dfa
    except Exception as e:
        raise FormatValidationError(
            '%s: cannot build the pattern DFA: %s' % (name, e))
    if dfa is None:
        raise FormatValidationError(
            '%s: the pattern accepts an empty covertext, which does not end '
            'with its terminator %r' % (name, terminator))

    failure = _kmp_failure(terminator)
    start = (dfa.start, 0, False)
    parents = {start: None}
    pending = deque([start])
    while pending:
        product = pending.popleft()
        dfa_state, matched, internal = product
        if dfa_state in dfa.accept_states:
            witness = _accepted_witness(parents, product)
            if matched != len(terminator):
                raise FormatValidationError(
                    '%s: the pattern accepts %r, which does not end with its '
                    'terminator %r' % (name, witness, terminator))
            if internal:
                raise FormatValidationError(
                    '%s: the pattern accepts %r, which contains terminator %r '
                    'before the end of the covertext'
                    % (name, witness, terminator))

        transitions = dfa.states[dfa_state].transitions
        for byte, next_dfa_state in sorted(transitions.items()):
            next_product = (
                next_dfa_state,
                _advance_match(terminator, failure, matched, byte),
                internal or matched == len(terminator),
            )
            if next_product in parents:
                continue
            parents[next_product] = (product, byte)
            pending.append(next_product)


def _check_sampled_prefixes(name, covertexts, lengths):
    """Check sampled prefix counts and allowed wire lengths."""
    prefix_len = fteproxy.defs.LENGTH_PREFIX_BYTES
    for covertext in covertexts:
        if len(covertext) < prefix_len:
            raise FormatValidationError(
                '%s: a sealed covertext of %d bytes is too short to carry its '
                '%d-byte length prefix' % (name, len(covertext), prefix_len))
        declared = int.from_bytes(covertext[:prefix_len], 'big')
        if declared != len(covertext) - prefix_len:
            raise FormatValidationError(
                '%s: a sealed covertext\'s length prefix says %d bytes but %d '
                'follow it' % (name, declared, len(covertext) - prefix_len))
        if len(covertext) not in lengths:
            raise FormatValidationError(
                '%s: a sealed covertext is %d bytes on the wire, which is not '
                'one of the lengths %r this format emits'
                % (name, len(covertext), lengths))


def _check_sampled_terminators(name, covertexts, terminator):
    """Confirm on real covertexts what :func:`check_terminator_uniqueness` proves."""
    for covertext in covertexts:
        if not covertext.endswith(terminator):
            raise FormatValidationError(
                '%s: a sealed covertext does not end with the terminator %r'
                % (name, terminator))
        if terminator in covertext[:-len(terminator)]:
            raise FormatValidationError(
                '%s: a sealed covertext carries the terminator %r before its '
                'end, so framing would cut it in half' % (name, terminator))


def frame_covertexts(wire, terminator):
    """Split a format-mode wire into covertexts on ``terminator``.

    The decoder's framing, without the keys: everything up to and including each
    terminator is one covertext. A trailing fragment with no terminator is
    returned as the last element, so a caller can tell a complete wire from a
    truncated one.
    """
    covertexts = []
    offset = 0
    while True:
        end = wire.find(terminator, offset)
        if end < 0:
            break
        end += len(terminator)
        covertexts.append(wire[offset:end])
        offset = end
    if offset < len(wire):
        covertexts.append(wire[offset:])
    return covertexts


def frame_length_prefixed(wire):
    """Split prefixed records, retaining prefixes and any incomplete final fragment."""
    prefix_len = fteproxy.defs.LENGTH_PREFIX_BYTES
    covertexts = []
    offset = 0
    while offset + prefix_len <= len(wire):
        declared = int.from_bytes(wire[offset:offset + prefix_len], 'big')
        end = offset + prefix_len + declared
        if end > len(wire):
            break
        covertexts.append(wire[offset:end])
        offset = end
    if offset < len(wire):
        covertexts.append(wire[offset:])
    return covertexts


def frame_spec_covertexts(wire, spec):
    """Split wire bytes using fixed, terminator, or length-prefix framing."""
    framing = fteproxy.defs.spec_framing(spec)
    if framing == fteproxy.defs.FRAMING_LENGTH_PREFIX:
        return frame_length_prefixed(wire)
    if framing == fteproxy.defs.FRAMING_TERMINATOR:
        return frame_covertexts(wire, fteproxy.defs.spec_terminator(spec))
    length = fteproxy.defs.spec_length(spec)
    return [wire[offset:offset + length]
            for offset in range(0, len(wire), length)]


def _modes_for(mode_hint):
    """Always test format mode; also test hybrid when the hint selects it."""
    if mode_hint == fteproxy.defs.MODE_HYBRID:
        return (fteproxy.defs.MODE_FORMAT, fteproxy.defs.MODE_HYBRID)
    return (fteproxy.defs.MODE_FORMAT,)


def _variable_lengths(name, spec):
    """The :class:`~fteproxy.record_layer.VariableLength` a spec describes.

    Building it proves every allowed length compiles and can carry a record;
    a length that cannot is a definitions bug that would otherwise surface as a
    connection which encodes fine and then cannot chunk.
    """
    import fteproxy

    ciphers = {}
    for length in fteproxy.defs.spec_allowed_lengths(spec):
        try:
            ciphers[length] = fteproxy._spec_cipher(spec, length, _KEY)
        except Exception as e:
            raise FormatValidationError(
                '%s: unusable at length %d, one of the lengths it would emit: '
                '%s' % (name, length, e))
    try:
        return fteproxy.record_layer.VariableLength(
            ciphers, fteproxy.defs.spec_terminator(spec),
            framing=fteproxy.defs.spec_framing(spec))
    except ValueError as e:
        raise FormatValidationError('%s: %s' % (name, e))


def validate_format(name, spec, samples=_SAMPLES):
    """Validate one format entry. Returns ``(name, length, capacity, mode_hint)``.

    ``length`` and ``capacity`` are reported at :func:`fteproxy.defs.spec_length`
    -- the length the handshake seals at, which for a variable-length format is
    its ``max_length``.

    Raises :class:`FormatValidationError` naming ``name`` on any failure.
    """
    import fteproxy  # deferred: fteproxy imports fteproxy.defs at import time
    import fteproxy.record_layer as rl

    if 'regex' not in spec:
        raise FormatValidationError('%s: no regex' % name)
    regex = spec['regex']
    try:
        fteproxy.defs._check_variable_keys(name, spec)
    except fteproxy.defs.DefinitionsError as e:
        raise FormatValidationError(str(e))
    length = fteproxy.defs.spec_length(spec)
    variable = fteproxy.defs.spec_is_variable(spec)
    terminator = fteproxy.defs.spec_terminator(spec)
    framing = fteproxy.defs.spec_framing(spec)
    prefixed = (framing == fteproxy.defs.FRAMING_LENGTH_PREFIX)
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
        capacity = fteproxy._spec_cipher(spec, length, _KEY).max_plaintext_bytes
    except Exception as e:
        raise FormatValidationError(
            '%s: unusable at length %d: %s' % (name, length, e))
    if capacity < fteproxy.defs.MIN_CAPACITY:
        raise FormatValidationError(
            '%s: capacity %d bytes at length %d is below the %d-byte floor'
            % (name, capacity, length, fteproxy.defs.MIN_CAPACITY))

    lengths = None
    if variable:
        # Every length this format may emit has to compile and carry a record,
        # and -- when the framing is a terminator -- that terminator has to be
        # unique to a covertext's end. Both before the round trip, since the
        # round trip depends on them. A length-prefix format has no terminator;
        # its framing is checked on the emitted covertexts below, because the
        # prefix is not in the pattern for a static check to read.
        lengths = _variable_lengths(name, spec)
        if not prefixed:
            check_terminator_uniqueness(name, regex, terminator)

    # Require a capable hybrid header after checking each base-regex length.
    # A separate hybrid_regex must satisfy this independently of the base capacity.
    header_length = fteproxy.hybrid_header_length(spec)
    if header_length is None:
        raise FormatValidationError(
            '%s: none of the covertext lengths %r has room for a %d-byte hybrid '
            'header, so this format cannot run in hybrid mode'
            % (name, fteproxy.defs.spec_allowed_lengths(spec),
               rl.HYBRID_HEADER_BYTES))

    pattern = _compiled_regex(regex)
    try:
        hybrid_pattern = _compiled_regex(
            fteproxy.defs.spec_hybrid_regex(spec))
    except Exception as e:
        raise FormatValidationError('%s: invalid hybrid_regex: %s' % (name, e))
    for mode in _modes_for(mode_hint):
        hybrid = (mode == fteproxy.defs.MODE_HYBRID)
        # A variable-length format varies only in format mode: a hybrid record
        # is a fixed-length header plus an authenticated body (optionally with
        # protocol framing). That header goes at ``header_length``, the shortest
        # length that holds one, which is what a live session uses -- so the
        # round trip exercises the frame size the product actually writes rather
        # than one only this check ever sees.
        variable_lengths = None if hybrid else lengths
        frame_length = header_length if hybrid else length
        def header_cipher():
            if hybrid:
                return fteproxy._framed_cipher(
                    fteproxy.defs.spec_hybrid_regex(spec), frame_length, _KEY,
                    framing)
            return fteproxy._spec_cipher(spec, frame_length, _KEY)
        body_framing = (fteproxy.defs.spec_hybrid_framing(spec) if hybrid
                        else fteproxy.defs.HYBRID_FRAMING_RAW)
        encoder = rl.Encoder(
            cipher=header_cipher(),
            body_cipher=fteproxy._make_body_cipher(_KEY) if hybrid else None,
            variable=variable_lengths, hybrid_framing=body_framing)
        decoder = rl.Decoder(
            cipher=header_cipher(),
            body_cipher=fteproxy._make_body_cipher(_KEY) if hybrid else None,
            variable=variable_lengths, hybrid_framing=body_framing)
        for i in range(samples):
            payload = os.urandom((i * 7) % (encoder.capacity + 1))
            encoder.push(payload)
            wire = encoder.pop()
            if hybrid and wire:
                header = wire[:frame_length]
                message = (header[fteproxy.defs.LENGTH_PREFIX_BYTES:]
                           if prefixed else header)
                if not hybrid_pattern.fullmatch(message):
                    raise FormatValidationError(
                        '%s: a sealed hybrid header does not match the '
                        'hybrid_regex' % name)
            else:
                covertexts = frame_spec_covertexts(wire, spec)
                if prefixed:
                    _check_sampled_prefixes(
                        name, covertexts,
                        variable_lengths.lengths
                        if variable_lengths is not None else (length,))
                elif variable_lengths is not None:
                    _check_sampled_terminators(name, covertexts, terminator)
                for covertext in covertexts:
                    # The framing prefix is not in the format's language: the
                    # regex describes the message it announces, so it is the
                    # message that has to match.
                    message = (covertext[fteproxy.defs.LENGTH_PREFIX_BYTES:]
                               if prefixed else covertext)
                    if not pattern.fullmatch(message):
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

    Loads the packaged release file directly, resolving historical aliases.
    Raises :class:`FileNotFoundError` for an unknown release and
    :class:`FormatValidationError` naming any offending formats.
    """
    path = fteproxy.defs._release_path(release)
    with open(path) as fh:
        definitions = json.load(fh)
    return _validate_definitions(definitions, source='release %s' % release,
                                 samples=samples)


def validate_fragment(path, samples=_SAMPLES):
    """Validate one standalone JSON object of format entries from path."""
    with open(path) as fh:
        definitions = json.load(fh)
    return _validate_definitions(definitions,
                                 source=os.path.basename(path), samples=samples)
