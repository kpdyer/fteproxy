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

import threading
import time
from decimal import Decimal
import fte.conf
SILENT = 0
ERROR = 10
WARN = 20
INFO = 30
DEBUG = 40


def displayMsg(msg, newline=True):
    mode = ('testing' if fte.conf.getValue('runtime.mode')
            == None else fte.conf.getValue('runtime.mode'))
    log_file = open('fte-' + mode + '.log', 'a')
    if newline:
        log_file.write(str(msg) + '\n')
    else:
        log_file.write(str(msg))
    log_file.close()


def error(log_level, msg, newline=True):
    if ERROR <= max(log_level, fte.conf.getValue('loglevel.default')):
        if fte.conf.getValue('runtime.mode'):
            msg = 'ERROR(' + fte.conf.getValue('runtime.mode') + '): ' \
                + str(msg)
        else:
            msg = 'ERROR: ' + str(msg)
        displayMsg(str(msg), newline)


def warn(log_level, msg, newline=True):
    if WARN <= max(log_level, fte.conf.getValue('loglevel.default')):
        if fte.conf.getValue('runtime.mode'):
            msg = 'WARN(' + fte.conf.getValue('runtime.mode') + '): ' \
                + str(msg)
        else:
            msg = 'WARN: ' + str(msg)
        displayMsg(str(msg), newline)


def info(log_level, msg, newline=True):
    if INFO <= max(log_level, fte.conf.getValue('loglevel.default')):
        if fte.conf.getValue('runtime.mode'):
            msg = 'INFO(' + fte.conf.getValue('runtime.mode') + '): ' \
                + str(msg)
        else:
            msg = 'INFO: ' + str(msg)
        displayMsg(str(msg), newline)


def debug(log_level, msg, newline=True):
    if DEBUG <= max(log_level, fte.conf.getValue('loglevel.default')):
        if fte.conf.getValue('runtime.mode'):
            msg = 'DEBUG(' + fte.conf.getValue('runtime.mode') + '): ' \
                + str(msg)
        else:
            msg = 'DEBUG: ' + str(msg)
        displayMsg(str(msg), newline)


_msgs = []


def performance(action, start_or_stop, input_time=None):
    if fte.conf.getValue('runtime.performance.debug'):
        global _msgs
        if input_time is None:
            input_time = time.time()
        msg = [str(threading.current_thread().ident), action,
               start_or_stop, str(Decimal(input_time))]
        msg = ','.join(msg)
        _msgs.append(msg)


def performance_write():
    if fte.conf.getValue('runtime.performance.debug'):
        global _msgs
        mode = fte.conf.getValue('runtime.mode')
        with open('performance-' + mode + '.log', 'a') as f:
            f.write('\n'.join(_msgs))
        _msgs = []