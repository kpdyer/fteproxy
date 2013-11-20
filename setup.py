#!/usr/bin/env python

from distutils.core import setup
from distutils.core import Extension

import os

if os.name=='nt':
    boost_libs = ['boost_python-mt','boost_system-mt','boost_filesystem-mt']
    extra_compile_args = ['-O3',
                          #'-fstack-protector-all',
                          '-D_FORTIFY_SOURCE',
                          '-fPIE',
                         ]
else:
    boost_libs = ['boost_python','boost_system','boost_filesystem']
    extra_compile_args = ['-O3',
                          '-fstack-protector-all',
                          '-D_FORTIFY_SOURCE',
                          '-fPIE',
                         ]
    
fte_cDFA = Extension('fte.cDFA',
                     include_dirs=['fte',
                                   'thirdparty/re2',
                                   '/usr/local/include'],
                     library_dirs=['thirdparty/re2/obj',
                                   '/usr/local/lib'],
                     extra_compile_args=extra_compile_args,
                     extra_link_args=['-fPIC',
                                      'thirdparty/re2/obj/libre2.a'
                                      ],
                     libraries=['gmp',
                                'gmpxx',
                                're2',
                                'python2.7',
                                ]+boost_libs,
                     sources=['fte/cDFA.cc'])

setup(name='Format-Transforming Encrypion (FTE)',
      version='0.2.0',
      description='FTE',
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://github.com/redjack/fte-proxy',
      packages=['fte',
                'fte.defs',
                'fte.tests',
                ],
      scripts=['bin/fteproxy',
               'bin/socksproxy'],
      package_data={'fte.defs': ['*.json', 'fte/defs/*.json']},
      ext_modules=[fte_cDFA],
      )
