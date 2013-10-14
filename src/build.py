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
    #cmd += ' -l' + fte.conf.getValue('build.python_lib')
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
    localBuildDir = os.path.abspath('./../third-party/opt')
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


def doDist():
    with open('VERSION') as f:
        VERSION = f.read().strip()
    PLATFORM = platform.system().lower()
    ARCH = os.uname()[4]
    RELEASE_NAME = VERSION + '.' + PLATFORM + '.' + ARCH

    LD_LIBRARY_PATH = os.path.join(
        os.path.abspath('..'), 'third-party', 'opt', 'lib')

    executeCommand('rm -rfv dist')
    os.makedirs('dist')
    os.makedirs('dist/fte_relay-' + RELEASE_NAME)
    os.makedirs('dist/fte_relay-' + RELEASE_NAME + '/bin')

    executeCommand('LD_LIBRARY_PATH=' + LD_LIBRARY_PATH +
                   ':$LD_LIBRARY_PATH python ../third-party/pyinstaller-2.0/pyinstaller.py -F ./bin/fte_relay')

    executeCommand(
        'mv -v dist/fte_relay dist/fte_relay-' + RELEASE_NAME + '/bin/')
    executeCommand('cp -v ../README dist/fte_relay-' + RELEASE_NAME + '/')
    executeCommand('cp -v ../COPYING dist/fte_relay-' + RELEASE_NAME + '/')
    executeCommand('cp -rfv languages dist/fte_relay-' + RELEASE_NAME + '/')
    executeCommand('cp -rfv formats dist/fte_relay-' + RELEASE_NAME + '/')

    executeCommand('cd dist && tar cvf fte_relay-' +
                   RELEASE_NAME + '.tar fte_relay-' + RELEASE_NAME)
    executeCommand('gzip -9 dist/fte_relay-' + RELEASE_NAME + '.tar')


def doTor():
    with open('VERSION') as f:
        VERSION = f.read().strip()
    PLATFORM = platform.system().lower()
    ARCH = os.uname()[4]
    RELEASE_NAME = VERSION + '.' + PLATFORM + '.' + ARCH

    LATEST_TBB = None
    if PLATFORM == 'linux':
        if ARCH == 'i686':
            LATEST_TBB = 'https://www.torproject.org/dist/torbrowser/linux/tor-browser-gnu-linux-i686-2.3.25-10-dev-en-US.tar.gz'
        elif ARCH == 'x86_64':
            LATEST_TBB = 'https://www.torproject.org/dist/torbrowser/linux/tor-browser-gnu-linux-x86_64-2.3.25-10-dev-en-US.tar.gz'
    elif PLATFORM == 'darwin':
        if ARCH == 'i686':
            LATEST_TBB = 'https://www.torproject.org/dist/torbrowser/osx/TorBrowser-2.3.25-10-osx-i386-en-US.zip'
        elif ARCH == 'x86_64':
            LATEST_TBB = 'https://www.torproject.org/dist/torbrowser/osx/TorBrowser-2.3.25-10-osx-x86_64-en-US.zip'

    if not LATEST_TBB:
        print "Unsupported platform"
        sys.exit(0)

    TBB_FILENAME_TARGZ = LATEST_TBB.split('/')[-1]
    if PLATFORM == 'darwin':
        TBB_FILENAME_TAR = TBB_FILENAME_TARGZ
        TBB_FILENAME_ROOT = '.'.join(TBB_FILENAME_TARGZ.split('.')[:-1])
        TBB_FTE_FILENAME_TAR = TBB_FILENAME_ROOT + \
            '+[fte_relay-' + VERSION + '].zip'
    elif PLATFORM == 'linux':
        TBB_FILENAME_TAR = '.'.join(TBB_FILENAME_TARGZ.split('.')[:-1])
        TBB_FILENAME_ROOT = '.'.join(TBB_FILENAME_TARGZ.split('.')[:-2])
        TBB_FTE_FILENAME_TAR = TBB_FILENAME_ROOT + \
            '+[fte_relay-' + VERSION + '].tar'

    u = urllib2.urlopen(LATEST_TBB)
    with open('dist/' + TBB_FILENAME_TARGZ, 'w') as f:
        f.write(u.read())

    executeCommand('cd dist && tar zxvf ' + TBB_FILENAME_TARGZ)

    if PLATFORM == 'darwin':
        TOR_DIR = 'TorBrowser_en-US.app'
        TORRC = 'dist/' + TOR_DIR + '/Library/Vidalia/torrc'
    elif PLATFORM == 'linux':
        TOR_DIR = 'tor-browser_en-US'
        TORRC = 'dist/' + TOR_DIR + '/Data/Tor/torrc'

    with open(TORRC) as f:
        contents = f.read()

    contents += '\nSocks5Proxy 127.0.0.1:8080'
    with open(TORRC, 'w') as f:
        f.write(contents)

    if PLATFORM == 'darwin':
        executeCommand(
            'patch dist/' + TOR_DIR + '/Contents/MacOS/TorBrowserBundle < patches/TorBrowserBundle.patch')
    elif PLATFORM == 'linux':
        executeCommand(
            'patch dist/' + TOR_DIR + '/start-tor-browser < patches/start-tor-browser.patch')
    #executeCommand('rm dist/'+TBB_FILENAME_TARGZ)
    if PLATFORM == 'darwin':
        executeCommand('cd dist && cp -rfv fte_relay-' +
                       RELEASE_NAME + ' ' + TOR_DIR + '/Contents/MacOS/fte_relay')
    elif PLATFORM == 'linux':
        executeCommand('cd dist && cp -rfv fte_relay-' +
                       RELEASE_NAME + ' ' + TOR_DIR + '/App/fte_relay')
    executeCommand('rm dist/' + TBB_FILENAME_TARGZ)
    if PLATFORM == 'darwin':
        executeCommand(
            'cd dist && zip -r ' + TBB_FTE_FILENAME_TAR + ' ' + TOR_DIR)
    elif PLATFORM == 'linux':
        executeCommand(
            'cd dist && tar cvf ' + TBB_FTE_FILENAME_TAR + ' ' + TOR_DIR)
        executeCommand('cd dist && gzip -9 ' + TBB_FTE_FILENAME_TAR)

    executeCommand('cd dist && rm -rfv ' + TOR_DIR)
    executeCommand('cd dist && rm -rfv fte_relay-' + RELEASE_NAME)


def main():
    localBuildDir = os.path.abspath('./../third-party/opt')

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

    doDist()
    doTor()

if __name__ == '__main__':
    main()
