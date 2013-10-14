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

# You should have received a copy of the GNU General Public License
# along with FTE.  If not, see <http://www.gnu.org/licenses/>.

#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import multiprocessing
import platform
import fte.logger
PYTHON_VERSION = str(sys.version_info[0]) + '.' \
    + str(sys.version_info[1])
PLATFORM = platform.system().lower()


def getValue(key):
    return conf[key]


def setValue(key, value):
    conf[key] = value


def we_are_frozen():
    return hasattr(sys, "frozen")


def module_path():
    encoding = sys.getfilesystemencoding()
    if we_are_frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(__file__)


conf = {}
conf['modules.regex.enable'] = True
conf['general.base_dir'] = os.path.abspath(os.path.join(module_path(), '..'))
conf['general.pid_dir'] = getValue('general.base_dir')
conf['general.python_path'] = '/usr/bin'
conf['general.fte_dir'] = os.path.join(getValue('general.base_dir'))
conf['general.bin_dir'] = os.path.join(getValue('general.base_dir'),
                                       'bin')
conf['general.doc_dir'] = os.path.join(getValue('general.base_dir'),
                                       'doc')
conf['general.scripts_dir'] = os.path.join(getValue('general.base_dir'
                                                    ), 'scripts')
conf['general.formats_dir'] = os.path.join(getValue('general.fte_dir'),
                                           'formats')
conf['general.languages_dir'] = os.path.join(getValue('general.fte_dir'
                                                      ), 'languages')
conf['general.cfg_dir'] = os.path.join(getValue('general.languages_dir'
                                                ), 'cfgs')
conf['general.re_dir'] = os.path.join(getValue('general.languages_dir'
                                               ), 'regexs')
conf['general.fst_dir'] = conf['general.re_dir']
conf['general.dfa_dir'] = conf['general.re_dir']
conf['build.third_party_dir'] = os.path.join(getValue('general.base_dir'
                                                      ), '../third-party')
conf['build.openfst_path'] = \
    os.path.join(getValue('build.third_party_dir'), 'opt', 'bin')
conf['build.antlr_jar'] = os.path.join(getValue('build.third_party_dir'
                                                ), 'antlr/antlr-3.4.jar')
conf['build.antlr_lib'] = os.path.join(getValue('build.third_party_dir'
                                                ), 'libantlr3c-3.4/.libs')
conf['build.antlr_include'] = \
    os.path.join(getValue('build.third_party_dir'), 'libantlr3c-3.4')
conf['build.antlrc_include'] = \
    os.path.join(getValue('build.third_party_dir'),
                 'libantlr3c-3.4/include')
conf['build.re2_dir'] = '../third-party/re2-20130115'
conf['build.c_flags'] = '-O3'
conf['build.c_compiler'] = 'gcc'
conf['build.cpp_compiler'] = 'g++'
conf['build.cpp_flags'] = '-fPIC -O3'
conf['build.python_include'] = ['/usr/include/python' + PYTHON_VERSION,
                                '/usr/local/include/python'
                                + PYTHON_VERSION]
conf['build.gmp_include'] = \
    os.path.join(getValue('build.third_party_dir'), 'opt/include')
conf['build.gmp_lib'] = os.path.join(getValue('build.third_party_dir'),
                                     'opt/lib')
conf['build.gmpy_include'] = \
    os.path.join(getValue('build.third_party_dir'), 'gmpy-2.0.0b4/src')
conf['build.python_lib'] = 'python' + PYTHON_VERSION
conf['build.python_bin'] = 'python'
if PLATFORM == 'darwin':
    conf['build.boost_python'] = 'boost_python-mt'
    conf['build.boost_system'] = 'boost_system-mt'
else:
    conf['build.boost_python'] = 'boost_python'
    conf['build.boost_system'] = 'boost_system'
conf['runtime.mode'] = None
conf['runtime.console.debug'] = False
conf['runtime.performance.debug'] = False
conf['runtime.regex.negotiate'] = True
conf['runtime.tcp.timeout'] = 30
conf['runtime.fte.encrypter.key'] = 'FF' * 16 + '00' * 16
conf['runtime.fte.relay.server_timeout'] = 30
conf['runtime.fte.relay.client_timeout'] = 30
conf['runtime.tcp.relay.forceful_shutdown'] = True
conf['runtime.fte.relay.forceful_shutdown'] = True
conf['runtime.tcp.relay.nolinger'] = False
conf['runtime.fte.relay.nolinger'] = False
conf['runtime.tcp.relay.backlog'] = 5
conf['runtime.fte.relay.backlog'] = 5
conf['runtime.client.ip'] = '0.0.0.0'
conf['runtime.client.port'] = 8080
conf['runtime.client.workers'] = multiprocessing.cpu_count()
conf['runtime.client.worker_port'] = 9100
conf['runtime.server.ip'] = '128.105.214.241'
conf['runtime.server.port'] = 80
conf['runtime.server.workers'] = multiprocessing.cpu_count()
conf['runtime.server.worker_port'] = 9000
conf['runtime.socks.ip'] = '127.0.0.1'
conf['runtime.socks.port'] = 8081
conf['runtime.http_proxy.enable'] = False
conf['runtime.http_proxy.ip'] = None
conf['runtime.http_proxy.port'] = 3128
conf['runtime.state.upstream_language'] = 'intersection-http-request'
conf['runtime.state.downstream_language'] = 'intersection-http-response'
conf['runtime.fte.relay.clock_speed'] = 0.01
conf['runtime.fte.relay.select_speed'] = 0.001
conf['runtime.fte.tcp.relay.block_size'] = 2 ** 12
conf['runtime.fte.relay.encoder_block_size'] = 2 ** 12
conf['runtime.fte.relay.decoder_block_size'] = 2 ** 12
conf['runtime.fte.record_layer.max_cell_size'] = 2 ** 16
conf['learning.pcap_full_dir'] = None
conf['learning.pcap_split_dir'] = None
conf['learning.couchdb.ip'] = '127.0.0.1'
conf['learning.couchdb.port'] = 5984
conf['metrics.enable'] = False
conf['metrics.fte_bytes_sent'] = 0
conf['metrics.fte_bytes_received'] = 0
conf['metrics.actual_bytes_sent'] = 0
conf['metrics.actual_bytes_received'] = 0
conf['loglevel.default'] = fte.logger.SILENT
conf['loglevel.build'] = fte.logger.SILENT
conf['loglevel.scripts.regex2dfa'] = fte.logger.SILENT
conf['loglevel.fte.regex'] = fte.logger.SILENT
conf['loglevel.fte.relay'] = fte.logger.SILENT
conf['loglevel.fte.encoder'] = fte.logger.SILENT
conf['loglevel.fte.encrypter'] = fte.logger.SILENT
conf['loglevel.fte.tcp.relay'] = fte.logger.SILENT
conf['loglevel.bin.fte_server'] = fte.logger.SILENT
conf['loglevel.bin.fte_client'] = fte.logger.SILENT
conf['loglevel.fte.record_layer'] = fte.logger.SILENT
conf['loglevel.fte.format_package'] = fte.logger.SILENT
conf['formats'] = ['request-response']
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
for language in conf['formats']:
    conf['formats.' + language + '.markov_file'] = \
        os.path.join(getValue('general.fte_dir'), 'formats', language,
                     language + '.markov')
    conf['formats.' + language + '.partitions_file'] = \
        os.path.join(getValue('general.fte_dir'), 'formats', language,
                     language + '.partitions')