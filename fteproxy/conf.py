#!/usr/bin/env python
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


"""Our loglevel = 0|1|2|3"""
conf['runtime.loglevel'] = 1


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


"""The maximum number of bytes to segment for an outgoing message."""
conf['runtime.fteproxy.record_layer.max_cell_size'] = 2 ** 15


"""The default client-to-server language."""
conf['runtime.state.upstream_language'] = 'manual-http-request'


"""The default server-to-client language."""
conf['runtime.state.downstream_language'] = 'manual-http-response'


"""The default AE scheme key."""
conf['runtime.fteproxy.encrypter.key'] = 'FF' * 16 + '00' * 16


"""The default fixed_slice parameter to use for buildTable."""
conf['fteproxy.default_fixed_slice'] = 2 ** 8


"""The default definitions file to use."""
conf['fteproxy.defs.release'] = '20131224'
