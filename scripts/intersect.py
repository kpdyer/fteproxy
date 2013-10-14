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

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import glob
import os
import sys
sys.path.append('.')
import fte.conf
OPENFST_BIN = '../third-party/opt/bin'


def cleanDFA(dfa_file):
    retval = []
    with open(dfa_file) as f:
        contents = f.read()
    lines = contents.split('\n')
    for line in lines:
        if not line:
            continue
        entry = line.split('\t')
        if len(entry) == 4:
            entry[0] = str(int(entry[0], 16))
            entry[1] = str(int(entry[1], 16))
        else:
            entry[0] = str(int(entry[0], 16))
        if len(entry) == 1:
            retval.append(' '.join(entry))
        elif int(entry[2]) > 0 and int(entry[3]) > 0:
            retval.append(' '.join(entry))
    with open(dfa_file, 'w') as f:
        f.write('\n'.join(retval))


def execute(cmd):
    os.system(cmd)


def mergeFSTs(input_fsts, output_fst):
    print input_fsts
    if len(input_fsts) < 2:
        assert False
    for i in range(1, len(input_fsts)):
        if i == 1:
            fst_file_a = input_fsts[i - 1]
            fst_file_b = input_fsts[i]
        else:
            fst_file_a = output_fst
            fst_file_b = input_fsts[i]
        cmd = OPENFST_BIN + '/fstintersect ' + fst_file_a + ' ' \
            + fst_file_b + ' ' + output_fst + '.tmp'
        execute(cmd)
        cmd = 'mv ' + output_fst + '.tmp ' + output_fst
        execute(cmd)
    cmd = OPENFST_BIN + '/fstdeterminize  ' + output_fst + ' ' \
        + output_fst + '.tmp'
    execute(cmd)
    cmd = 'mv ' + output_fst + '.tmp ' + output_fst
    execute(cmd)
    cmd = OPENFST_BIN + '/fstminimize  ' + output_fst + ' ' \
        + output_fst + '.tmp'
    execute(cmd)
    cmd = 'mv ' + output_fst + '.tmp ' + output_fst
    execute(cmd)


os.system('rm -v ./languages/regexs/intersection-*.fst')
os.system('rm -v ./languages/regexs/intersection-*.dfa')
for protocol in ['http', 'ssh', 'smb']:
    for direction in ['request', 'response']:
        mergeable_fsts = glob.glob('./languages/regexs/*-' + protocol
                                   + '-' + direction + '-min.fst')
        to_remove = []
        for val in mergeable_fsts:
            if 'learned' in val:
                to_remove.append(val)
            elif 'scott' in val:
                to_remove.append(val)
            elif 'manual' in val:
                to_remove.append(val)
        for val in to_remove:
            mergeable_fsts.remove(val)
        mergeFSTs(mergeable_fsts, './languages/regexs/intersection-'
                  + protocol + '-' + direction + '-min.fst')
        cmd = OPENFST_BIN + '/fstprint'
        cmd += ' --isymbols=' \
            + os.path.join(fte.conf.getValue('general.re_dir'),
                           'isyms.txt')
        cmd += ' --osymbols=' \
            + os.path.join(fte.conf.getValue('general.re_dir'),
                           'osyms.txt')
        cmd += ' ./languages/regexs/intersection-' + protocol + '-' \
            + direction + '-min.fst'
        cmd += ' > ./languages/regexs/intersection-' + protocol + '-' \
            + direction + '.dfa'
        execute(cmd)