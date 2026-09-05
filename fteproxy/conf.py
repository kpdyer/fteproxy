#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Process-wide defaults.

What is left here is what a *library* user might want to change and what has
no better home: buffer sizes, timeouts, and which definitions file to read.
Everything that describes one run -- the listen address, the destination, the
formats, the keys -- comes from the command line or from
:func:`fteproxy.wrap_socket`, not from here. Until 1.0 those lived in this
dictionary too, which is why a value that never reached it could stop the
process working.
"""


import os
import sys


def getValue(key):
    return conf[key]


def setValue(key, value):
    conf[key] = value


def we_are_frozen():
    # All of the modules are built-in to the interpreter, e.g., by py2exe
    return hasattr(sys, "frozen")


def module_path():
    if we_are_frozen():
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(__file__)


conf = {}


"""The path for fte *.json definition files."""
if we_are_frozen():
    conf['general.defs_dir'] = os.path.join(module_path(), 'fteproxy', 'defs')
else:
    conf['general.defs_dir'] = os.path.join(module_path(), '..', 'fteproxy', 'defs')


"""The maximum number of queued connections for sockets"""
conf['runtime.fteproxy.relay.backlog'] = 100


"""The default socket timeout."""
conf['runtime.fteproxy.relay.socket_timeout'] = 30


"""The default socket accept timeout."""
conf['runtime.fteproxy.relay.accept_timeout'] = 0.1


"""Maximum concurrent server-side connection setups.

A setup owns a thread while it waits for the handshake, the client's OPEN,
and the destination dial.  Keeping this finite prevents unauthenticated peers
from turning the handshake timeout and rejection delay into an unbounded
number of threads and sockets.
"""
conf['runtime.fteproxy.relay.max_pending'] = 64


"""Maximum concurrent server-side setups from one source address.

The global limit remains the hard bound; this smaller fair-share limit keeps a
single address from occupying every setup slot.  Operators serving many users
behind one NAT can raise it, up to the global limit.
"""
conf['runtime.fteproxy.relay.max_pending_per_source'] = 8


"""Maximum established server-side sessions, globally and per source.

Setup admission protects the handshake path; these limits bound the sockets,
worker threads and destination connections retained after setup succeeds.
"""
conf['runtime.fteproxy.relay.max_active'] = 128
conf['runtime.fteproxy.relay.max_active_per_source'] = 64


"""Maximum concurrent client-listener setups, globally and per source.

SOCKS and fixed-forward listeners do work before a relay connection exists:
they may be waiting for a local SOCKS request or dialling the remote server.
Both limits remain necessary when ``--expose-listeners`` deliberately makes a
listener reachable from other machines.
"""
conf['runtime.fteproxy.relay.client_max_pending'] = 32
conf['runtime.fteproxy.relay.client_max_pending_per_source'] = 16


"""The default penalty after polling for network data, and not recieving anything.

Load-bearing, despite looking like a busy-wait tax: it is a GIL yield that
keeps a connection's two relay workers from convoying, and deleting it costs
an order of magnitude in a real two-process deployment. See PERFORMANCE.md."""
conf['runtime.fteproxy.relay.throttle'] = 0.01


"""How long either end waits for the handshake to complete."""
conf['runtime.fteproxy.handshake.timeout'] = 5


"""Record-layer framing mode.

'hybrid' (the default) formats a fixed-length header per record and carries an
authenticated ciphertext body: the DFA rank/unrank runs once per record, not
once per ~150 bytes, so bulk transfer runs close to raw-AEAD speed. Only each
record's header blends in with the target protocol; the body past it remains
high-entropy ciphertext. A carrier may add native framing around that body;
HTTP uses one complete chunked body per record.

'format' transforms every covertext byte into the target format, so the whole
stream is indistinguishable from the protocol: stronger against entropy or
statistical detectors, but much slower. Turn it on when you want full-stream
realism and can spend the throughput.

Since 1.0 this is the *client's* default choice, not a setting both endpoints
must match by hand: the client puts its choice in the handshake and the server
follows."""
conf['runtime.fteproxy.record_layer.mode'] = 'hybrid'


"""The base format name a client uses when it is given none.

A base name, not a direction: the request and response formats are derived
from it, and only the base travels in the handshake. The command line goes
further and picks the format matching the server's port (see
:func:`fteproxy.config.format_for_port`); this is the last-resort default for
a library caller that names none."""
conf['fteproxy.default_format'] = 'http'


"""Covertext length for definitions that carry no "length" key (the manual-*
and dummy-* formats)."""
conf['fteproxy.default_length'] = 2 ** 8


"""The default definitions file to use.

Since the 20260903 release that is the five cleartext protocols (http, ftp,
smtp, sip, dns), one entry per direction. The comprehensive shape catalog that
used to be the default is still shipped as 20260110 and is reachable with
``--defs 20260110``."""
conf['fteproxy.defs.release'] = '20260903'
