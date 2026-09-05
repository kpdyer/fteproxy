#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Process-wide defaults for definitions, buffers, timeouts, and relay limits.

Per-run addresses and keys come from the CLI or socket API. Library callers may
change these defaults with setValue before creating listeners or wrappers.
"""


import os
import sys


def getValue(key):
    return conf[key]


def setValue(key, value):
    conf[key] = value


def we_are_frozen():
    # Packaged executables may set sys.frozen (for example, py2exe).
    return hasattr(sys, "frozen")


def module_path():
    if we_are_frozen():
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(__file__)


conf = {}


# The directory containing release JSON files.
if we_are_frozen():
    conf['general.defs_dir'] = os.path.join(module_path(), 'fteproxy', 'defs')
else:
    conf['general.defs_dir'] = os.path.join(module_path(), '..', 'fteproxy', 'defs')


# Kernel listen backlog; separate from application setup limits.
conf['runtime.fteproxy.relay.backlog'] = 100


# Socket I/O timeout, in seconds.
conf['runtime.fteproxy.relay.socket_timeout'] = 30


# Accept-loop polling interval, in seconds.
conf['runtime.fteproxy.relay.accept_timeout'] = 0.1


# Concurrent server setups, including handshake, OPEN, and destination dial.
conf['runtime.fteproxy.relay.max_pending'] = 64


# Concurrent server setups per source IP; also subject to the global limit.
conf['runtime.fteproxy.relay.max_pending_per_source'] = 8


# Established server sessions, globally and per source IP.
conf['runtime.fteproxy.relay.max_active'] = 128
conf['runtime.fteproxy.relay.max_active_per_source'] = 64


# Concurrent client setups, shared across SOCKS and forward listeners.
conf['runtime.fteproxy.relay.client_max_pending'] = 32
conf['runtime.fteproxy.relay.client_max_pending_per_source'] = 16


# Idle-poll sleep, in seconds. Historical measurements: PERFORMANCE.md.
conf['runtime.fteproxy.relay.throttle'] = 0.01


# Handshake timeout, in seconds; server rejection adds a random delay.
conf['runtime.fteproxy.handshake.timeout'] = 5


# Socket API mode default. Hybrid uses FTE headers and encrypted bodies;
# format mode encodes typed payloads into covertexts. Neither guarantees
# normal protocol behavior. The CLI also applies URI and format hints.
conf['runtime.fteproxy.record_layer.mode'] = 'hybrid'


# Base name used when the socket API receives no format; CLI selection is separate.
conf['fteproxy.default_format'] = 'http'


# Wire length for definitions without a fixed length or range.
conf['fteproxy.default_length'] = 2 ** 8


# Default catalog. The older shape catalog remains available as 20260110.
conf['fteproxy.defs.release'] = '20260903'
