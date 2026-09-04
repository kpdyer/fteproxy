#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Realism harness: sample real covertexts and judge them like a DPI would.

Each of the five shipped protocols (phases F1-F5) adds a module here named for
the protocol -- ``http.py``, ``ftp.py``, ``smtp.py``, ``sip.py``, ``dns.py`` --
exposing one function::

    check(covertext: bytes) -> None

which raises (any exception) if ``covertext`` is not a structurally valid message
of that protocol, and returns ``None`` if it is. ``http.py`` MUST judge with an
independent parser (``http.server.BaseHTTPRequestHandler`` for a request line,
``email.parser`` for the header block); the line protocols use a strict grammar
check. A protocol's own test file feeds it a batch of sealed covertexts and
calls ``check`` on each, plus :func:`statistical_guard` over the batch.

The seal-padding rule (see ``docs/format-authoring.md``) is why this harness
samples through :func:`format_covertexts`, which drives the real record-layer
:class:`fteproxy.record_layer.Encoder` in **format** mode and cuts the wire back
into individual sealed covertexts -- by length for a fixed-length format, on the
terminator or on the length prefix for a variable-length one, exactly as the
decoder frames it. What comes back is always what went on the *wire*, framing
included, so ``dns.py`` sees the RFC 1035 length prefix its parser starts at. A bare
``fte.FTE.encrypt`` of a short message ranks low and unranks into a degenerate
covertext (one long run of the field's lowest character); a sealed covertext is
padded to the format's full capacity first, so its variable fields are filled
with high-entropy format bytes exactly as they are in production. Realism MUST
be judged on sealed covertexts, never on raw ``encrypt`` output.
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
    """``n`` individual sealed covertexts of one format.

    Drives the record layer's format-mode :class:`~fteproxy.record_layer.Encoder`
    (which seals: pads plaintext to the format's capacity with random bytes
    before encrypting) over ``n`` records of random payload, then cuts the
    resulting wire back into individual covertexts. This is the
    seal-padding-correct sampler the module docstring describes; do not sample
    with a bare ``fte.FTE.encrypt``.

    Called either with a **definitions spec** (the dict from a ``parts/*.json``
    fragment or a release) or, for a fixed-length format, with its
    ``regex, length`` directly:

    * a **fixed-length** format is chunked at its one capacity and the wire is
      sliced at ``length``, exactly as the decoder frames it;
    * a **variable-length** format picks a length per record, so the payloads
      are varied to exercise the choice and the wire is framed the way that
      format's decoder frames it -- on its terminator, or on the length prefix
      each record carries. The covertexts come back at the mix of lengths a
      real stream would carry.

    Every covertext is returned exactly as it went on the wire. For a
    ``length-prefix`` format that includes the framing prefix, which is what a
    protocol parser reads first (and what ``realism.dns`` checks against the
    bytes that follow it); a regex match, on the other hand, has to be taken on
    the message behind the prefix, since the prefix is framing rather than
    language.
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
        # One record each time, at a payload size that walks the whole range a
        # real stream produces, so the sample carries the mix of covertext
        # lengths the length choice is meant to produce.
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
    """An ``(Encoder, Decoder)`` pair for one definitions entry, in one mode.

    The same wiring :func:`fteproxy._session_channel` does for a live
    connection, minus the handshake: in ``format`` mode a variable-length format
    also gets the ciphers for every length it may emit, and in ``hybrid`` mode
    it does not, because a hybrid record is a fixed-length header plus a raw
    body -- sealed at :func:`fteproxy.hybrid_header_length`, the shortest length
    that holds one, not at ``max_length``. A protocol's test file uses this so
    it exercises the framing the product actually uses rather than a hand-rolled
    approximation of it.
    """
    length = (fteproxy.hybrid_header_length(spec) if hybrid
              else fteproxy.defs.spec_length(spec))
    variable = (None if hybrid or not fteproxy.defs.spec_is_variable(spec)
                else fteproxy._variable_lengths_for_spec(spec, key))
    body = fteproxy._make_body_cipher(key) if hybrid else None
    return (rl.Encoder(cipher=fteproxy._spec_cipher(spec, length, key),
                       body_cipher=body, variable=variable),
            rl.Decoder(cipher=fteproxy._spec_cipher(spec, length, key),
                       body_cipher=body, variable=variable))


def allowed_lengths(spec):
    """The covertext lengths one definitions entry may emit, ascending."""
    return fteproxy.defs.spec_allowed_lengths(spec)


def statistical_guard(covertexts, max_run_fraction=0.5):
    """Raise :class:`RealismError` if any covertext is dominated by one byte.

    A single character running for more than ``max_run_fraction`` of a
    covertext's length is the signature of a badly shaped regex whose only
    variable field is one long low-entropy run -- the degenerate covertext the
    seal-padding rule exists to avoid. A healthy format fills its variable
    fields with high-entropy bytes, so its longest run is short.
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
    """Prove the sampler and the guard work on the inline reference format.

    Returns the sampled covertexts on success; raises on any failure.
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
