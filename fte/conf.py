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
import tempfile


def getValue(key):
    return conf[key]


def setValue(key, value):
    conf[key] = value


def module_path():
    return os.path.dirname(__file__)


conf = {}
conf['general.base_dir'] = os.path.abspath(os.path.join(module_path()))
conf['general.pid_dir'] = tempfile.gettempdir()
conf['general.fte_dir'] = os.path.join(getValue('general.base_dir'))
conf['general.bin_dir'] = os.path.join(getValue('general.base_dir'), 'bin')
conf['general.scripts_dir'] = os.path.join(getValue('general.base_dir'), 'scripts')
conf['runtime.mode'] = None
conf['runtime.tcp.relay.backlog'] = 5
conf['runtime.fte.relay.backlog'] = 5
conf['runtime.client.ip'] = '127.0.0.1'
conf['runtime.client.port'] = 8079
conf['runtime.server.ip'] = 'tor.fte-proxy.org'
conf['runtime.server.port'] = 8080
conf['runtime.proxy.ip'] = '127.0.0.1'
conf['runtime.proxy.port'] = 8081
conf['runtime.fte.relay.socket_timeout'] = 0.001
conf['runtime.fte.tcp.relay.block_size'] = 2 ** 12
conf['runtime.fte.relay.encoder_block_size'] = 2 ** 12
conf['runtime.fte.relay.decoder_block_size'] = 2 ** 12
conf['runtime.fte.record_layer.max_cell_size'] = 2 ** 16


conf['runtime.state.upstream_language'] = 'manual-http-request'
conf['runtime.state.downstream_language'] = 'manual-http-response'
conf['fte.default_max_len'] = 512
conf['runtime.fte.encrypter.key'] = 'FF' * 16 + '00' * 16
conf['fte.defs.release'] = '20131023'
