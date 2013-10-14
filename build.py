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
import os
import platform
import sys
import string
import urllib2
import multiprocessing

sys.path.append('.')

import fte.conf
import fte.logger

LOG_LEVEL = fte.conf.getValue('loglevel.build')
ARCH = ('-m64' if os.uname()[4] == 'x86_64' else '-m32')


class BuildFailedException(Exception):

    pass


def executeCommand(cmd):
    print cmd
    fte.logger.debug(LOG_LEVEL, cmd)
    os.system(cmd)


def compileRegexso():
    cmd = fte.conf.getValue('build.cpp_compiler')
    cmd += ' ' + fte.conf.getValue('build.cpp_flags')
    cmd += ' -fPIC ' + ARCH
    cmd += ' -c ' + os.path.join(fte.conf.getValue('general.fte_dir'),
                                 'fte', 'cRegex.cc')
    cmd += ' -o ' + os.path.join(fte.conf.getValue('general.fte_dir'),
                                 'fte', 'cRegex.o')
    cmd += ' -I ' + os.path.join(fte.conf.getValue('general.fte_dir'),
                                 'fte')
    cmd += ' -I' \
        + str(' -I'.join(fte.conf.getValue('build.python_include')))
    cmd += ' -I' + fte.conf.getValue('build.gmp_include')
    cmd += ' -I' + fte.conf.getValue('build.gmpy_include')
    cmd += ' -I/opt/local/include'
    cmd += ' -DPYTHON_MODULE'
    executeCommand(cmd)

    cmd = fte.conf.getValue('build.cpp_compiler')
    cmd += ' -shared'
    cmd += ' ' + \
        os.path.join(fte.conf.getValue('general.fte_dir'), 'fte', 'cRegex.o')
    cmd += ' -L/usr/local/lib'
    cmd += ' -L/usr/local/Cellar/python/2.7.5/Frameworks/Python.framework/Versions/2.7/lib'
    cmd += ' -l' + fte.conf.getValue('build.python_lib')
    cmd += ' -lgmp'
    cmd += ' -l' + fte.conf.getValue('build.boost_python')
    cmd += ' -l' + fte.conf.getValue('build.boost_system')
    cmd += ' -o ' + os.path.join(fte.conf.getValue('general.fte_dir'),
                                 'fte', 'cRegex.so')
    executeCommand(cmd)


def compileRE2DFA():
    localBuildDir = os.path.abspath('./third-party/opt')
    cmd = 'cd ' + fte.conf.getValue('build.re2_dir') \
        + ' && make -j' + \
        str(multiprocessing.cpu_count()) + ' obj/libre2.a && make install'
    executeCommand(cmd)

    cmd = fte.conf.getValue('build.cpp_compiler')
    cmd += ' ' + fte.conf.getValue('build.cpp_flags')
    cmd += ' -fPIC ' + ARCH
    cmd += ' -I' + fte.conf.getValue('build.re2_dir')
    cmd += ' -c'
    cmd += ' ' + os.path.join(fte.conf.getValue('general.fte_dir'),
                              'fte', 're2dfa.cc')
    cmd += ' -pthread'
    cmd += ' -I/opt/local/include'
    cmd += ' -o ' + os.path.join(fte.conf.getValue('general.fte_dir'),
                                 'fte', 're2dfa.o')
    executeCommand(cmd)

    cmd = fte.conf.getValue('build.cpp_compiler')
    cmd += ' ' + fte.conf.getValue('build.cpp_flags')
    cmd += ' -o ' + os.path.join(fte.conf.getValue('general.bin_dir'),
                                 're2dfa')
    cmd += ' ' + os.path.join(fte.conf.getValue('general.fte_dir'),
                              'fte', 're2dfa.o')
    cmd += ' ' + os.path.join(fte.conf.getValue(
        'build.re2_dir'), 'obj', 'libre2.a')
    cmd += ' -pthread'
    executeCommand(cmd)


def compileDFAs():
    executeCommand(fte.conf.getValue('build.python_bin') + ' '
                   + os.path.join(fte.conf.getValue('general.scripts_dir'
                                                    ), 'regex2dfa.py'))
    executeCommand(fte.conf.getValue('build.python_bin') + ' '
                   + os.path.join(fte.conf.getValue('general.scripts_dir'
                                                    ), 'intersect.py'))


def verifyArtifacts(artifacts):
    for artifact in artifacts:
        if not os.path.exists(artifact):
            raise BuildFailedException('Artifact ' + artifact
                                       + ' does not exist')
        else:
            fte.logger.info(LOG_LEVEL, 'Successfully built ' + artifact)
    return True


def main():
    localBuildDir = os.path.abspath('./third-party/opt')

    compileRegexso()
    verifyArtifacts([os.path.join(fte.conf.getValue('general.fte_dir'),
                    'fte', 'cRegex.so')])

    compileRE2DFA()
    verifyArtifacts(
        [os.path.join(fte.conf.getValue('general.fte_dir'), 'bin', 're2dfa'),
         os.path.join(
             fte.conf.getValue(
        'build.re2_dir'), 'obj', 'libre2.a'),
                    ])

    compileDFAs()

if __name__ == '__main__':
    main()
