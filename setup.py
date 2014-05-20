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

package_data_files = []
package_data_files += ['VERSION']
for filename in glob.glob('fteproxy/defs/*.json'):
    jsonFile = filename.split('/')[-1]
    package_data_files += ['defs/'+jsonFile]
package_data = {'fteproxy': package_data_files}

with open('README') as file:
    long_description = file.read()

setup(name='fteproxy',
      long_description=long_description,
      console=['./bin/fteproxy'],
      test_suite='fteproxy.tests.suite',
      zipfile="fteproxy.zip",
      package_data=package_data,
      options={"py2exe": {
          "bundle_files": 2,
          "compressed": True,
          "dll_excludes": ["w9xpopen.exe"],
      }
      },
      version=FTEPROXY_RELEASE,
      description='fteproxy',
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://fteproxy.org/',
      packages=['fteproxy', 'fteproxy.defs', 'fteproxy.tests'],
      install_requires=['fte','twisted','pyptlib','obfsproxy'],
      entry_points = {
        'console_scripts': [
            'fteproxy = fteproxy.cli:main'
            ]
        },
      )
