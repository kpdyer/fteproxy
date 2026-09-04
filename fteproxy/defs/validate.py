#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate that a format definition is actually usable as written.

Loading a release (:func:`fteproxy.defs.check_capacities`) already proves every
regex compiles and holds a handshake. This module goes further and exercises a
format the way a live connection does, so a definition that compiles but cannot
carry traffic is caught before it ships:

* build the libfte cipher at every length the format may emit and require
  ``max_plaintext_bytes >=`` the capacity floor
  (:data:`fteproxy.defs.MIN_CAPACITY`) at the length the handshake seals at;
* require at least one allowed length to have room for a hybrid header
  (:data:`fteproxy.record_layer.HYBRID_HEADER_BYTES`), since a format with none
  cannot run in ``hybrid`` mode and a session asking for it is refused rather
  than framed some other way. ``defs-check`` reports the length that is used;
* round-trip a batch of random payloads through
  :class:`fteproxy.record_layer.Encoder`/:class:`~fteproxy.record_layer.Decoder`
  in the format's ``mode_hint`` -- and in *both* modes when the hint is
  ``hybrid``, since the client's ``--mode`` may override it either way. The
  hybrid pass frames at the header length a live session uses, not at
  ``max_length``;
* assert every sealed **format-mode** covertext fully matches the regex, so the
  bytes on the wire really are drawn from the format's language -- for a
  ``length-prefix`` format, after taking the framing prefix off, since the
  prefix is not part of the language the regex describes;
* for a **terminator**-framed format, prove its terminator can only ever be the
  final suffix of a covertext -- statically, from the pattern, and again over
  sampled covertexts. Framing depends on that, so it is checked here rather
  than assumed of whoever wrote the regex. A ``length-prefix`` format has no
  terminator to prove anything about; what is checked instead is that every
  emitted prefix announces exactly the bytes that follow it and that the wire
  length it implies is one the format declared.

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

#: Backslash escapes the regex2dfa dialect gives a non-literal meaning *outside*
#: a character class. Inside a class there are no escapes at all (see the
#: dialect notes in ``docs/format-authoring.md``), which is why the class scanner
#: below reads raw characters.
_ESCAPES = {'r': '\r', 'n': '\n', 't': '\t', 'f': '\f', 'v': '\v'}

#: Regex operators that produce no covertext byte of their own.
_METACHARACTERS = '()|+*?'

#: Stands for one character drawn from a character class in a literal skeleton.
#: Sound because the class check runs first: no class in a variable-length
#: format may admit a terminator byte, so whatever a class produces can only
#: separate its neighbours, never take part in a terminator.
_ANY = '\x00'

#: Most literal skeletons one pattern may expand to before the check gives up.
#: Every alternation branch and every optional atom multiplies the count, so a
#: pathological pattern could blow up; the shipped formats expand to fewer than
#: 30 each. Exceeding it is a validation *failure*, never a pass: a pattern too
#: complex to prove is a pattern whose framing is not proven.
_SKELETON_CAP = 4096


def _scan_pattern(pattern):
    """Split a pattern into ``('literal', ch)`` and ``('class', members)`` atoms.

    ``members`` is the set of characters a ``[...]`` class admits, or ``None``
    for a negated class (which admits so much that it is refused outright).
    Raises :class:`ValueError` on a pattern this scanner cannot read, so an
    unreadable pattern fails validation rather than passing unchecked.
    """
    atoms = []
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == '\\':
            if index + 1 >= len(pattern):
                raise ValueError('pattern ends in a backslash')
            escaped = pattern[index + 1]
            atoms.append(('literal', _ESCAPES.get(escaped, escaped)))
            index += 2
        elif character == '[':
            close = pattern.find(']', index + 1)
            if close < 0:
                raise ValueError('unterminated character class')
            atoms.append(('class', _class_members(pattern[index + 1:close])))
            index = close + 1
        elif character in _METACHARACTERS:
            index += 1
        else:
            atoms.append(('literal', character))
            index += 1
    return atoms


def _literal_skeletons(pattern):
    """Every literal skeleton the pattern can produce, as a set of strings.

    A *skeleton* is one covertext with each character-class run collapsed to a
    single :data:`_ANY` placeholder: it keeps exactly the literal characters and
    exactly the adjacencies between them, which is all a terminator search
    needs. Unlike deleting the operators and concatenating what is left, this
    expands each alternation branch separately, so it does not invent an
    adjacency between two branches that never occur together *and* does not
    miss the adjacency between a branch's last character and whatever follows
    the group -- the case a single concatenated skeleton silently drops.

    Repetition (``+``, ``*``) is expanded to one and two copies: two exposes the
    junction where a repeated unit meets itself. A terminator that only appears
    across *three* or more copies of one repeated group would slip through; the
    sampled check in :func:`validate_format` is the second net for that.

    Raises :class:`ValueError` on a pattern this cannot read or that expands
    past :data:`_SKELETON_CAP`.
    """
    skeletons, index = _skeleton_alternation(pattern, 0)
    if index != len(pattern):
        raise ValueError('unexpected %r at offset %d'
                         % (pattern[index], index))
    return skeletons


def _capped(strings):
    if len(strings) > _SKELETON_CAP:
        raise ValueError('the pattern expands to more than %d literal '
                         'skeletons, too many to prove the terminator unique'
                         % _SKELETON_CAP)
    return strings


def _skeleton_alternation(pattern, index):
    """``a|b|c`` -> the union of the branches. Stops at ``)`` or the end."""
    options = set()
    while True:
        branch, index = _skeleton_sequence(pattern, index)
        options = _capped(options | branch)
        if index < len(pattern) and pattern[index] == '|':
            index += 1
            continue
        return options, index


def _skeleton_sequence(pattern, index):
    """A run of atoms -> every concatenation of their expansions."""
    strings = {''}
    while index < len(pattern) and pattern[index] not in '|)':
        atom, index = _skeleton_atom(pattern, index)
        strings = _capped({prefix + suffix
                           for prefix in strings for suffix in atom})
    return strings, index


def _skeleton_atom(pattern, index):
    """One atom and its quantifier -> the strings it can contribute."""
    character = pattern[index]
    if character == '(':
        strings, index = _skeleton_alternation(pattern, index + 1)
        if index >= len(pattern) or pattern[index] != ')':
            raise ValueError('unbalanced (')
        index += 1
        repeatable = True
    elif character == '[':
        close = pattern.find(']', index + 1)
        if close < 0:
            raise ValueError('unterminated character class')
        index = close + 1
        # A class cannot produce a terminator byte, so one placeholder stands
        # for any number of them: repeating it would change no adjacency.
        strings, repeatable = {_ANY}, False
    elif character == '\\':
        if index + 1 >= len(pattern):
            raise ValueError('pattern ends in a backslash')
        strings = {_ESCAPES.get(pattern[index + 1], pattern[index + 1])}
        index += 2
        repeatable = True
    elif character == ')':
        raise ValueError('unbalanced )')
    else:
        strings = {character}
        index += 1
        repeatable = True

    if index < len(pattern) and pattern[index] in '+*?':
        quantifier = pattern[index]
        index += 1
        variants = set(strings)
        if repeatable and quantifier in '+*':
            variants |= {first + second
                         for first in strings for second in strings}
        if quantifier in '*?':
            variants.add('')
        strings = _capped(variants)
    return strings, index


def _class_members(body):
    """The characters a ``[...]`` class body admits; ``None`` if it is negated.

    Ranges (``a-z``) expand; a ``-`` first or last is itself. There are no
    backslash escapes inside a class in this dialect, so every character stands
    for itself.
    """
    if body.startswith('^'):
        return None
    members = set()
    index = 0
    while index < len(body):
        if index + 2 < len(body) and body[index + 1] == '-':
            for point in range(ord(body[index]), ord(body[index + 2]) + 1):
                members.add(chr(point))
            index += 3
        else:
            members.add(body[index])
            index += 1
    return members


def check_terminator_uniqueness(name, regex, terminator):
    """Prove from the pattern that only a covertext's suffix is the terminator.

    Two conditions, both conservative -- a pattern this refuses may still be
    safe, but a pattern it accepts cannot produce the terminator anywhere but at
    the end:

    1. **No character class admits a terminator byte.** With CRLF terminators
       that means no field may contain a CR or an LF at all. A weaker rule (no
       single class admits *both*) leaves the case where one class supplies the
       CR and the next atom the LF, which would need the whole language to rule
       out; forbidding the bytes outright is what makes the literal check below
       exhaustive, because every terminator byte then comes from a literal.
    2. **No literal skeleton contains the terminator before its end.** A
       skeleton (:func:`_literal_skeletons`) is one covertext with each
       character-class run collapsed to a placeholder, expanded over every
       alternation branch and every optional atom. Since rule 1 leaves the
       literals as the only source of terminator bytes, a terminator that
       occurs in no skeleton occurs in no covertext -- except as the trailing
       literal the pattern ends with.

    Raises :class:`FormatValidationError` naming ``name``.
    """
    terminator_text = terminator.decode('latin-1')
    if _ANY in terminator_text:
        raise FormatValidationError(
            '%s: a terminator containing a NUL cannot be checked' % name)
    body = regex
    if body.startswith('^'):
        body = body[1:]
    if body.endswith('$'):
        body = body[:-1]
    if not body.endswith(terminator_text):
        raise FormatValidationError(
            '%s: the pattern does not end with its terminator %r, so the '
            'terminator is not the covertext\'s final suffix'
            % (name, terminator))
    body = body[:-len(terminator_text)]

    try:
        atoms = _scan_pattern(body)
    except ValueError as e:
        raise FormatValidationError('%s: cannot read the pattern: %s' % (name, e))

    terminator_set = set(terminator_text)
    for kind, value in atoms:
        if kind != 'class':
            continue
        if value is None:
            raise FormatValidationError(
                '%s: a negated character class may admit a terminator byte; a '
                'variable-length format must spell its classes out' % name)
        overlap = sorted(value & terminator_set)
        if overlap:
            raise FormatValidationError(
                '%s: a character class admits %r, a byte of the terminator %r, '
                'so a covertext could carry the terminator inside it'
                % (name, ''.join(overlap), terminator))

    try:
        skeletons = _literal_skeletons(body)
    except ValueError as e:
        raise FormatValidationError('%s: cannot read the pattern: %s' % (name, e))
    for skeleton in skeletons:
        text = skeleton + terminator_text
        if text.find(terminator_text) != len(text) - len(terminator_text):
            raise FormatValidationError(
                '%s: the pattern\'s literal text can produce the terminator %r '
                'before the end of a covertext' % (name, terminator))


def _check_sampled_prefixes(name, covertexts, lengths):
    """The length-prefix counterpart of :func:`_check_sampled_terminators`.

    Framing here is not a property of the language to be proven from the
    pattern -- the prefix is not in the pattern at all -- it is a property of
    what the record layer emits. So it is checked on the wire: every covertext
    carries a prefix announcing exactly the bytes that follow it, and the wire
    length that implies is one the format declared, which is the only thing the
    decoder will accept.
    """
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
    """Split a format-mode wire into covertexts on their length prefixes.

    The decoder's framing for a ``length-prefix`` format, without the keys: each
    record is a :data:`fteproxy.defs.LENGTH_PREFIX_BYTES` big-endian count
    followed by that many bytes, and the prefix is kept on the covertext because
    it is part of what went on the wire. A trailing fragment too short for the
    length its prefix announces is returned as the last element, so a caller can
    tell a complete wire from a truncated one.
    """
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
    """Split a format-mode wire the way *this* format's decoder frames it.

    One dispatch point for the three framings, so a caller that holds a
    definitions entry never has to ask which one it is: fixed-length slices,
    terminator framing, or length prefixes.
    """
    framing = fteproxy.defs.spec_framing(spec)
    if framing == fteproxy.defs.FRAMING_LENGTH_PREFIX:
        return frame_length_prefixed(wire)
    if framing == fteproxy.defs.FRAMING_TERMINATOR:
        return frame_covertexts(wire, fteproxy.defs.spec_terminator(spec))
    length = fteproxy.defs.spec_length(spec)
    return [wire[offset:offset + length]
            for offset in range(0, len(wire), length)]


def _modes_for(mode_hint):
    """Which record-layer modes to exercise for a given ``mode_hint``.

    ``format`` is always exercised (it is where the regex is checked); a
    ``hybrid`` format is exercised in both modes because either end's ``--mode``
    can select the other one.
    """
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

    for length in fteproxy.defs.spec_allowed_lengths(spec):
        try:
            fteproxy._spec_cipher(spec, length, _KEY)
        except Exception as e:
            raise FormatValidationError(
                '%s: unusable at length %d, one of the lengths it would emit: '
                '%s' % (name, length, e))
    try:
        return fteproxy._variable_lengths_for_spec(spec, _KEY)
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

    # A format has to have somewhere to put a hybrid header, or it cannot run in
    # hybrid mode at all -- and a session that asked for hybrid would be refused
    # outright (:class:`fteproxy.HybridUnsupportedError`) rather than quietly
    # framed some other way. Checked after the per-length build above, so a
    # format with an unusable length is reported as that rather than as this.
    # The capacity floor already guarantees a header fits for anything that gets
    # this far -- the length it is measured at is one of the allowed lengths and
    # MIN_CAPACITY dwarfs a header -- so this states the requirement rather than
    # leaving it standing on a coincidence between two unrelated constants.
    header_length = fteproxy.hybrid_header_length(spec)
    if header_length is None:
        raise FormatValidationError(
            '%s: none of the covertext lengths %r has room for a %d-byte hybrid '
            'header, so this format cannot run in hybrid mode'
            % (name, fteproxy.defs.spec_allowed_lengths(spec),
               rl.HYBRID_HEADER_BYTES))

    pattern = _compiled_regex(regex)
    for mode in _modes_for(mode_hint):
        hybrid = (mode == fteproxy.defs.MODE_HYBRID)
        # A variable-length format varies only in format mode: a hybrid record
        # is a fixed-length header plus a raw body. That header goes at
        # ``header_length``, the shortest length that holds one, which is what a
        # live session uses -- so the round trip exercises the frame size the
        # product actually writes rather than one only this check ever sees.
        variable_lengths = None if hybrid else lengths
        frame_length = header_length if hybrid else length
        encoder = rl.Encoder(
            cipher=fteproxy._spec_cipher(spec, frame_length, _KEY),
            body_cipher=fteproxy._make_body_cipher(_KEY) if hybrid else None,
            variable=variable_lengths)
        decoder = rl.Decoder(
            cipher=fteproxy._spec_cipher(spec, frame_length, _KEY),
            body_cipher=fteproxy._make_body_cipher(_KEY) if hybrid else None,
            variable=variable_lengths)
        for i in range(samples):
            payload = os.urandom((i * 7) % (encoder.capacity + 1))
            encoder.push(payload)
            wire = encoder.pop()
            if not hybrid:
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
