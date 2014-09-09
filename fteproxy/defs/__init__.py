#!/usr/bin/env python
# -*- coding: utf-8 -*-



import os
import json

import fteproxy.conf


class InvalidRegexName(Exception):
    pass

_definitions = None


def load_definitions():
    global _definitions

    if _definitions == None:
        def_dir = os.path.join(fteproxy.conf.getValue('general.defs_dir'))
        def_file = fteproxy.conf.getValue('fteproxy.defs.release') + '.json'
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
        fixed_slice = fteproxy.conf.getValue('fteproxy.default_fixed_slice')

    return fixed_slice
