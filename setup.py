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

from distutils import sysconfig
from distutils.core import setup
from distutils.core import Extension

import glob
import sys
import os
if os.name == 'nt':
    import py2exe

with open('fte/VERSION') as fh:
    FTEPROXY_RELEASE = fh.read().strip()

if os.name == 'nt':
    libraries = ['gmp.dll', 'gmpxx.dll']
else:
    libraries = ['gmp', 'gmpxx']

fte_cDFA = Extension('fte.cDFA',
                     include_dirs=['fte',
                                   'thirdparty/re2',
                                   'thirdparty/gmp/include',
                                   ],
                     library_dirs=['thirdparty/re2/obj',
                                   'thirdparty/gmp/lib',
                                   ],
                     extra_compile_args=['-O3',
                                         '-fPIE',
                                         ],
                     extra_link_args=['thirdparty/re2/obj/libre2.a',
                                      '-Wl,-undefined,dynamic_lookup',
                                      ],
                     libraries=libraries,
                     sources=['fte/rank_unrank.cc', 'fte/cDFA.cc'])

data_files = []
if os.name == 'nt':
    data_files = [('.', ['libgmp-10.dll', 'python27.dll'])]

fte_module_path = os.path.join(sysconfig.get_python_lib(), 'fte')
defs_module_path = os.path.join(sysconfig.get_python_lib(), 'fte', 'defs')
dfas_module_path = os.path.join(sysconfig.get_python_lib(), 'fte', 'tests', 'dfas')
data_files += [(fte_module_path, ['fte/VERSION'])]
data_files += [(defs_module_path, glob.glob('fte/defs/*.json'))]
data_files += [(dfas_module_path, glob.glob('fte/tests/dfas/*.dfa'))]
data_files += [(dfas_module_path, glob.glob('fte/tests/dfas/*.regex'))]

setup(name='fteproxy',
      console=['./bin/fteproxy'],
      zipfile="fteproxy.zip",
      data_files=data_files,
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
      url='https://github.com/kpdyer/fteproxy',
      ext_modules=[fte_cDFA],
      packages=['fte', 'fte.defs', 'fte.tests', 'fte.tests.dfas'],
      )
