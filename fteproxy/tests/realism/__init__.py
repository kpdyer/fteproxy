#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sample sealed covertexts and check selected structural properties.

Each protocol module exposes check(covertext), which raises on a failed check.
HTTP uses standard-library parsers; the other modules parse selected protocol
shapes independently of the definitions regex. These are limited structural
checks, not full conformance tests or models of a deployed traffic classifier.

format_covertexts samples real format-mode records, including random seal
padding and external framing. Direct libfte encryption of short unpadded
messages can produce systematic low-rank prefixes and is not representative
of these session records. statistical_guard checks only long same-byte runs.
"""

import json
import os
import re

import fteproxy
import fteproxy.defs
import fteproxy.defs.validate
import fteproxy.record_layer as rl


class RealismError(Exception):
    """A sampled covertext failed a structural or statistical realism check."""


_KEY = b'\x00' * 32


def format_covertexts(spec_or_regex, length=None, n=2000):
    """Return n sampled, sealed format-mode covertexts, including wire framing.

    Accept a definitions spec or a fixed regex/length pair. Fixed formats use full
    payload capacity; variable formats cycle through payload sizes and split the
    wire with the declared framing. This exercises length selection without
    claiming to reproduce a particular application's traffic distribution.
    """
    if isinstance(spec_or_regex, dict):
        spec = spec_or_regex
        regex = spec['regex']
        length = fteproxy.defs.spec_length(spec)
    else:
        regex, spec = spec_or_regex, None

    if spec is None or not fteproxy.defs.spec_is_variable(spec):
        cipher = (fteproxy._make_cipher(regex, length, _KEY) if spec is None
                  else fteproxy._spec_cipher(spec, length, _KEY))
        encoder = rl.Encoder(cipher=cipher)  # format mode: one covertext/chunk
        encoder.push(os.urandom(n * encoder.capacity))
        wire = encoder.pop()
        return [wire[i:i + length] for i in range(0, len(wire), length)][:n]

    variable = fteproxy._variable_lengths_for_spec(spec, _KEY)
    encoder = rl.Encoder(cipher=fteproxy._spec_cipher(spec, length, _KEY),
                         variable=variable)
    wire = b''
    for i in range(n):
        # Cycle through payload sizes to exercise the length-selection heuristic.
        encoder.push(os.urandom(1 + (i * 37) % variable.capacity))
        wire += encoder.pop()
    return frame_wire(wire, spec)[:n]


def frame_covertexts(wire, terminator):
    """Split a format-mode wire into covertexts on ``terminator``."""
    return fteproxy.defs.validate.frame_covertexts(wire, terminator)


def frame_wire(wire, spec):
    """Split a format-mode wire the way one definitions entry's decoder does."""
    return fteproxy.defs.validate.frame_spec_covertexts(wire, spec)


def record_layer_pair(spec, hybrid=False, key=_KEY):
    """Build an (Encoder, Decoder) pair for one spec without a handshake.

    Use the runtime's allowed lengths, hybrid-header selection, and body framing.
    The supplied test key is reused; real sessions derive separate directional keys.
    """
    length = (fteproxy.hybrid_header_length(spec) if hybrid
              else fteproxy.defs.spec_length(spec))
    variable = (None if hybrid or not fteproxy.defs.spec_is_variable(spec)
                else fteproxy._variable_lengths_for_spec(spec, key))
    body = fteproxy._make_body_cipher(key) if hybrid else None
    def header_cipher():
        if hybrid:
            return fteproxy._framed_cipher(
                fteproxy.defs.spec_hybrid_regex(spec), length, key,
                fteproxy.defs.spec_framing(spec))
        return fteproxy._spec_cipher(spec, length, key)
    body_framing = (fteproxy.defs.spec_hybrid_framing(spec) if hybrid
                    else fteproxy.defs.HYBRID_FRAMING_RAW)
    return (rl.Encoder(cipher=header_cipher(), body_cipher=body,
                       variable=variable, hybrid_framing=body_framing),
            rl.Decoder(cipher=header_cipher(), body_cipher=body,
                       variable=variable, hybrid_framing=body_framing))


def allowed_lengths(spec):
    """The covertext lengths one definitions entry may emit, ascending."""
    return fteproxy.defs.spec_allowed_lengths(spec)


def statistical_guard(covertexts, max_run_fraction=0.5):
    """Reject a covertext with a same-byte run above max_run_fraction of its length.

    This catches a simple degeneracy; passing does not establish protocol realism.
    """
    for index, covertext in enumerate(covertexts):
        if not covertext:
            continue
        longest = 1
        run = 1
        previous = covertext[0]
        for byte in covertext[1:]:
            if byte == previous:
                run += 1
                if run > longest:
                    longest = run
            else:
                run = 1
                previous = byte
        if longest > max_run_fraction * len(covertext):
            raise RealismError(
                'covertext %d has a %d-byte run of 0x%02x, more than %.0f%% of '
                'its %d bytes' % (index, longest, previous,
                                  max_run_fraction * 100, len(covertext)))


def load_part(proto):
    """The ``fteproxy/defs/parts/<proto>.json`` fragment as a dict."""
    path = os.path.join(os.path.dirname(fteproxy.defs.__file__),
                        'parts', proto + '.json')
    with open(path) as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Self-test with an inline reference format
#
# Not one of the five real protocols: a tiny made-up format used only to prove
# the sampler produces regex-matching sealed covertexts and that the guard
# accepts a varied covertext while rejecting a degenerate one.
# --------------------------------------------------------------------------- #

#: A high-entropy variable field (the path) inside fixed literal structure.
REFERENCE_REGEX = r'^GET /[a-zA-Z0-9]+ HTTP/1\.1\r\nHost: [a-z0-9.-]+\r\n\r\n$'
REFERENCE_LENGTH = 512


def self_test():
    """Check the sampler and repetition guard with a small reference format.

    Return the sampled covertexts, or raise on failure.
    """
    covertexts = format_covertexts(REFERENCE_REGEX, REFERENCE_LENGTH, n=64)
    pattern = re.compile(REFERENCE_REGEX.encode('latin-1'), re.DOTALL)
    for covertext in covertexts:
        if not pattern.fullmatch(covertext):
            raise RealismError('reference sampler produced a non-matching '
                               'covertext')
    # A real sealed covertext of a healthy format passes the guard ...
    statistical_guard(covertexts)
    # ... and a degenerate single-byte run is rejected.
    try:
        statistical_guard([b'a' * REFERENCE_LENGTH])
    except RealismError:
        pass
    else:
        raise RealismError('statistical_guard failed to reject a degenerate '
                           'covertext')
    return covertexts
