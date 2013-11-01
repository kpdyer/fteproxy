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
import json

import fte.conf


class InvalidRegexName(Exception):
    pass


def load_definitions():
    # TODO: Cache file, such that we don't have to reload each time
    
    def_dir = os.path.join(fte.conf.getValue('general.base_dir'), 'defs')
    def_file = fte.conf.getValue('fte.defs.release') + '.json'
    def_abspath = os.path.join(def_dir, def_file)

    with open(def_abspath) as fh:
        definitions = json.load(fh)

    return definitions


def getRegex(format_name):
    definitions = load_definitions()
    try:
        regex = definitions[format_name]['regex']
    except KeyError:
        raise InvalidRegexName(format_name)

    return regex


def getMaxLen(format_name):
    definitions = load_definitions()
    try:
        max_len = definitions[format_name]['max_len']
    except KeyError:
        max_len = fte.conf.getValue('fte.default_max_len')

    return max_len
