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

if sys.argv[1]=='py2exe':
    ext_modules = []
else:
    ext_modules = [fte_cDFA]

setup(name='fteproxy',
      console=['./bin/fteproxy'],
      zipfile="fteproxy.zip",
      options={"py2exe": {
             "optimize": 2,
             "includes": ["twisted", "pyptlib", "obfsproxy", "Crypto"],
                         }
      },
      version=FTEPROXY_RELEASE,
      description='fteproxy',
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://github.com/kpdyer/fteproxy',
      ext_modules=ext_modules,
      )
