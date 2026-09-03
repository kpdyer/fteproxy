#!/usr/bin/env python3
# -*- coding: utf-8 -*-



import os
import sys
import tempfile


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


"""The base path for the location of the fteproxy.* modules."""
if we_are_frozen():
    conf['general.base_dir'] = module_path()
else:
    conf['general.base_dir'] = os.path.join(module_path(), '..')


"""Directory containing binary executables"""
if we_are_frozen():
    conf['general.bin_dir'] = os.path.join(module_path())
else:
    conf['general.bin_dir'] = os.path.join(module_path(), '..', 'bin')


"""The path for fte *.json definition files."""
if we_are_frozen():
    conf['general.defs_dir'] = os.path.join(module_path(), 'fteproxy', 'defs')
else:
    conf['general.defs_dir'] = os.path.join(module_path(), '..', 'fteproxy', 'defs')


"""The location that we store *.pid files, such that we can kill fteproxy from the command line."""
conf['general.pid_dir'] = tempfile.gettempdir()


"""Our runtime mode: client|server|test"""
conf['runtime.mode'] = None


"""The maximum number of queued connections for sockets"""
conf['runtime.fteproxy.relay.backlog'] = 100


"""Our client-side ip:port to listen for incoming connections"""
conf['runtime.client.ip'] = '127.0.0.1'
conf['runtime.client.port'] = 8079


"""Our server-side ip:port to listen for connections from fteproxy clients"""
conf['runtime.server.ip'] = '127.0.0.1'
conf['runtime.server.port'] = 8080


"""Our proxy server, where the fteproxy server forwards outgoing connections."""
conf['runtime.proxy.ip'] = '127.0.0.1'
conf['runtime.proxy.port'] = 8081


"""The default socket timeout."""
conf['runtime.fteproxy.relay.socket_timeout'] = 30


"""The default socket accept timeout."""
conf['runtime.fteproxy.relay.accept_timeout'] = 0.1


"""The default penalty after polling for network data, and not recieving anything."""
conf['runtime.fteproxy.relay.throttle'] = 0.01


"""The default timeout when establishing a new fteproxy socket."""
conf['runtime.fteproxy.negotiate.timeout'] = 5


"""Record-layer framing mode.

'hybrid' (the default) formats a fixed-length header per record and carries the
body as raw authenticated bytes: the DFA rank/unrank runs once per record, not
once per ~150 bytes, so bulk transfer runs close to raw-AEAD speed. Only each
record's header blends in with the target protocol; the body past it is
high-entropy ciphertext. This is the behavior fteproxy shipped on libfte 0.3.

'format' transforms every covertext byte into the target format, so the whole
stream is indistinguishable from the protocol: stronger against entropy or
statistical detectors, but much slower. Turn it on when you want full-stream
realism and can spend the throughput. Both endpoints must use the same mode."""
conf['runtime.fteproxy.record_layer.mode'] = 'hybrid'


"""The default client-to-server language."""
conf['runtime.state.upstream_language'] = 'manual-http-request'


"""The default server-to-client language."""
conf['runtime.state.downstream_language'] = 'manual-http-response'


"""The key used when neither --key nor --key-file is given. It is public (it
is in this file), so it gives no confidentiality or integrity; fteproxy warns at
startup when it is in use. Always supply a secret shared by both endpoints."""
DEFAULT_KEY = b'\xFF' * 16 + b'\x00' * 16
conf['runtime.fteproxy.encrypter.key'] = DEFAULT_KEY


"""Covertext length for definitions that carry no "length" key (the manual-*
and dummy-* formats)."""
conf['fteproxy.default_length'] = 2 ** 8


"""The default definitions file to use."""
conf['fteproxy.defs.release'] = '20260110'
