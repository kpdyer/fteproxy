#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of FTE.
#
# FTE is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# FTE is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with FTE.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import tempfile


def getValue(key):
    return conf[key]


def setValue(key, value):
    conf[key] = value


def we_are_frozen():
    return hasattr(sys, "frozen")


def module_path():
    if we_are_frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(__file__)


conf = {}
conf['general.base_dir'] = os.path.abspath(os.path.join(module_path()))
conf['general.pid_dir'] = tempfile.gettempdir()
conf['general.fte_dir'] = os.path.join(getValue('general.base_dir'))
conf['general.bin_dir'] = os.path.join(getValue('general.base_dir'),
                                       'bin')
conf['general.scripts_dir'] = os.path.join(getValue('general.base_dir'
                                                    ), 'scripts')
conf['general.formats_dir'] = os.path.join(getValue('general.fte_dir'),
                                           'formats')
conf['general.re_dir'] = os.path.join(getValue('general.fte_dir'
                                               ), 'dfas')
conf['runtime.mode'] = None
conf['runtime.fte.encrypter.key'] = 'FF' * 16 + '00' * 16
conf['runtime.tcp.relay.backlog'] = 5
conf['runtime.fte.relay.backlog'] = 5
conf['runtime.client.ip'] = '0.0.0.0'
conf['runtime.client.port'] = 8079
conf['runtime.server.ip'] = '128.105.214.241'
conf['runtime.server.port'] = 8080
conf['runtime.socks.ip'] = '127.0.0.1'
conf['runtime.socks.port'] = 8081
conf['runtime.state.upstream_language'] = 'intersection-http-request'
conf['runtime.state.downstream_language'] = 'intersection-http-response'
conf['runtime.fte.relay.socket_timeout'] = 0.01
#conf['runtime.fte.relay.clock_speed'] = 0.01
#conf['runtime.fte.relay.select_speed'] = 0.001
conf['runtime.fte.tcp.relay.block_size'] = 2 ** 12
conf['runtime.fte.relay.encoder_block_size'] = 2 ** 12
conf['runtime.fte.relay.decoder_block_size'] = 2 ** 12
conf['runtime.fte.record_layer.max_cell_size'] = 2 ** 16

conf['languages.regex'] = []
for type in ['l7', 'yaf1', 'yaf2', 'appid', 'intersection', 'manual']:
    for protocol in ['http', 'ssh', 'smb']:
        for direction in ['request', 'response']:
            conf['languages.regex'].append(type + '-' + protocol + '-'
                                           + direction)
for lang in conf['languages.regex']:
    conf['languages.regex.' + lang + '.mtu'] = 128
    conf['languages.regex.' + lang + '.allow_ae_bits'] = True
    conf['languages.regex.' + lang + '.fixed_slice'] = True
conf['languages.regex.manual-http-request.allow_ae_bits'] = False
conf['languages.regex.manual-ssh-request.mtu'] = 99
conf['languages.regex.manual-ssh-response.mtu'] = 99
conf['languages.regex.zero-one.mtu'] = 32
conf['languages.regex.zero-one.fixed_slice'] = False
conf['languages.regex.zero-one.allow_ae_bits'] = True
conf['languages.regex.identity.mtu'] = 32
conf['languages.regex.identity.fixed_slice'] = False
conf['languages.regex.identity.allow_ae_bits'] = True
