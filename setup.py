#!/usr/bin/env python

from distutils.core import setup
from distutils.core import Extension

import os
import glob
if os.name=='nt':
    import py2exe

if os.name=='nt':
    libraries = ['boost_python-mgw48-1_45',
                  'boost_filesystem-mgw48-1_45',
                  'boost_system-mgw48-1_45',
                  'python27',
                 ]
    extra_compile_args = ['-O3',
                          '-D_FORTIFY_SOURCE',
                          '-fPIE',
                         ]
else:
    libraries = ['boost_python','boost_system','boost_filesystem','python2.7']
    extra_compile_args = ['-O3',
                          '-fstack-protector-all',
                          '-D_FORTIFY_SOURCE',
                          '-fPIE',
                         ]
    
fte_cDFA = Extension('fte.cDFA',
                     include_dirs=['fte',
                                   'thirdparty/re2'],
                     library_dirs=['thirdparty/re2/obj'],
                     extra_compile_args=extra_compile_args,
                     extra_link_args=['-fPIC',
                                      'thirdparty/re2/obj/libre2.a',
                                      '-LC:\\Boost\\lib',
                                      ],
                     libraries=['gmp',
                                'gmpxx',
                                're2','pthread',
                                ]+libraries,
                     sources=['fte/cDFA.cc'])

setup(name='Format-Transforming Encrypion (FTE)',
      console=['./bin/fteproxy'],
      options={"py2exe":{
                        "optimize":2,
                        "compressed":True,
                        "bundle_files":1,
                        }
              },
      version='0.2.0',
      description='FTE',
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://github.com/redjack/fte-proxy',
      packages=['fte',
                'fte.defs',
                'fte.tests',
                'fte.tests.dfas',
                ],
      scripts=['bin/fteproxy',
               'bin/socksproxy'],
      package_data={'fte.defs': ['*.json', 'fte/defs/*.json']},
      ext_modules=[fte_cDFA],
      )
