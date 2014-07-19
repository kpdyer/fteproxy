#!/usr/bin/env python

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

from setuptools import setup
from setuptools import Extension

import glob
import sys
import os
if os.name == 'nt':
    import py2exe

with open('fteproxy/VERSION') as fh:
    FTEPROXY_RELEASE = fh.read().strip()

setup(name='fteproxy',
      console=['./bin/fteproxy'],
      zipfile="fteproxy.zip",
      options={"py2exe": {
          "dll_excludes": ["w9xpopen.exe"],
      }
      },
      version=FTEPROXY_RELEASE,
      description='fteproxy',
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://github.com/kpdyer/fteproxy',
      packages=['fteproxy', 'fteproxy.defs', 'fteproxy.tests'],
      install_requires=['txsocks', 'parsley', 'pyptlib', 'obfsproxy', 'twisted', 'fte']
      )
