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

import time
import os
import sys
sys.path.append('.')
import fte.conf
import fte.logger
LOG_LEVEL = fte.conf.getValue('loglevel.scripts.regex2dfa')


def executeCommand(cmd):
    print cmd
    fte.logger.debug(LOG_LEVEL, cmd)
    os.system(cmd)


def cleanDFA(dfa_file):
    retval = []
    with open(dfa_file) as f:
        contents = f.read()
    lines = contents.split('\n')
    for line in lines:
        if not line:
            continue
        entry = line.split(' ')
        if len(entry) == 4:
            entry[0] = str(int(entry[0], 16))
            entry[1] = str(int(entry[1], 16))
        else:
            entry[0] = str(int(entry[0], 16))
        retval.append(' '.join(entry))
    with open(dfa_file, 'w') as f:
        f.write('\n'.join(retval))


def buildDFA(LANGUAGE):
    sys.stdout.flush()
    start = time.time()
    cmd = os.path.join(fte.conf.getValue('general.bin_dir'), 're2dfa')
    cmd += ' ' + os.path.join(fte.conf.getValue('general.re_dir'),
                              LANGUAGE + '.regex')
    cmd += ' > ' + os.path.join(fte.conf.getValue('general.dfa_dir'),
                                LANGUAGE + '.dfa')
    executeCommand(cmd)
    cleanDFA(os.path.join(fte.conf.getValue('general.dfa_dir'),
             LANGUAGE + '.dfa'))
    start = time.time()
    cmd = os.path.join(fte.conf.getValue('build.openfst_path'),
                       'fstcompile')
    cmd += ' --isymbols=' \
        + os.path.join(fte.conf.getValue('general.re_dir'), 'isyms.txt')
    cmd += ' --osymbols=' \
        + os.path.join(fte.conf.getValue('general.re_dir'), 'osyms.txt')
    cmd += ' ' + os.path.join(fte.conf.getValue('general.dfa_dir'),
                              LANGUAGE + '.dfa')
    cmd += ' ' + os.path.join(fte.conf.getValue('general.fst_dir'),
                              LANGUAGE + '.fst')
    fte.logger.debug(LOG_LEVEL, cmd)
    executeCommand(cmd)
    cmd = os.path.join(fte.conf.getValue('build.openfst_path'),
                       'fstminimize')
    cmd += ' ' + os.path.join(fte.conf.getValue('general.fst_dir'),
                              LANGUAGE + '.fst')
    cmd += ' ' + os.path.join(fte.conf.getValue('general.fst_dir'),
                              LANGUAGE + '-min.fst')
    fte.logger.debug(LOG_LEVEL, cmd)
    executeCommand(cmd)
    cmd = os.path.join(fte.conf.getValue('build.openfst_path'),
                       'fstprint')
    cmd += ' --isymbols=' \
        + os.path.join(fte.conf.getValue('general.re_dir'), 'isyms.txt')
    cmd += ' --osymbols=' \
        + os.path.join(fte.conf.getValue('general.re_dir'), 'osyms.txt')
    cmd += ' ' + os.path.join(fte.conf.getValue('general.fst_dir'),
                              LANGUAGE + '-min.fst')
    cmd += ' ' + os.path.join(fte.conf.getValue('general.dfa_dir'),
                              LANGUAGE + '.dfa')
    fte.logger.debug(LOG_LEVEL, cmd)
    executeCommand(cmd)
    finish = time.time()
    fte.logger.info(LOG_LEVEL, 'Successfully compiled DFA for '
                    + LANGUAGE + ' in ' + str(round(finish - start, 2))
                    + 's')
    return True


if __name__ == '__main__':
    dirList = os.listdir(fte.conf.getValue('general.re_dir'))
    dirList.sort()
    for filename in dirList:
        if not filename.endswith('regex'):
            continue
        f = open(os.path.join(fte.conf.getValue('general.re_dir'),
                 filename), 'r')
        contents = f.read()
        contents = contents.strip()
        f.close()
        f = open(os.path.join(fte.conf.getValue('general.re_dir'),
                 filename), 'w')
        f.write(contents)
        f.close()
        buildDFA(filename.split('/')[-1].split('.')[0])
