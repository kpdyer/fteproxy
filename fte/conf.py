#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of fteproxy.
#
# fteproxy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# fteproxy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with fteproxy.  If not, see <http://www.gnu.org/licenses/>.

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


"""The base path for the location of the fte.* modules."""
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
    conf['general.defs_dir'] = os.path.join(module_path(), 'fte', 'defs')
else:
    conf['general.defs_dir'] = os.path.join(module_path(), '..', 'fte', 'defs')


"""The location that we store *.pid files, such that we can kill fteproxy from the command line."""
conf['general.pid_dir'] = tempfile.gettempdir()


"""Our runtime mode: client|server|test"""
conf['runtime.mode'] = None


"""The maximum number of queued connections for sockets"""
conf['runtime.fte.relay.backlog'] = 100


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
conf['runtime.fte.relay.socket_timeout'] = 0.001


"""The default timeout when establishing a new fteproxy socket."""
conf['runtime.fte.negotiate.timeout'] = 5


"""The maximum number of bytes to segment for an outgoing message."""
conf['runtime.fte.record_layer.max_cell_size'] = 2 ** 14


"""The default client-to-server language."""
conf['runtime.state.upstream_language'] = 'manual-http-request'


"""The default server-to-client language."""
conf['runtime.state.downstream_language'] = 'manual-http-response'


"""The default AE scheme key."""
conf['runtime.fte.encrypter.key'] = 'FF' * 16 + '00' * 16


"""The default fixed_slice parameter to use for buildTable."""
conf['fte.default_fixed_slice'] = 2 ** 8


"""The default definitions file to use."""
conf['fte.defs.release'] = '20131224'
