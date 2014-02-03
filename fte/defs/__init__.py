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
import json

import fte.conf


class InvalidRegexName(Exception):
    pass

_definitions = None
def load_definitions():
    global _definitions

    if _definitions == None:
       def_dir = os.path.join(fte.conf.getValue('general.defs_dir'))
       def_file = fte.conf.getValue('fte.defs.release') + '.json'
       def_abspath = os.path.join(def_dir, def_file)

       with open(def_abspath) as fh:
           _definitions = json.load(fh)

    return _definitions


def getRegex(format_name):
    definitions = load_definitions()
    try:
        regex = definitions[format_name]['regex']
    except KeyError:
        raise InvalidRegexName(format_name)

    return regex


def getFixedSlice(format_name):
    definitions = load_definitions()
    try:
        fixed_slice = definitions[format_name]['fixed_slice']
    except KeyError:
        fixed_slice = fte.conf.getValue('fte.default_fixed_slice')

    return fixed_slice
