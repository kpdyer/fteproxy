#!/usr/bin/env python

from distutils.core import setup
from distutils.core import Extension

fte_cDFA = Extension('fte.cDFA',
                     include_dirs=['fte',
                                   'third-party/re2'],
                     library_dirs=['third-party/re2/obj'],
                     extra_link_args=['-static'],
                     extra_compile_args=[#'-fstack-protector-all',
                                         #'-D_FORTIFY_SOURCE',
                                         #'-fPIE', 
                                         '-O3'],
                     libraries=['gmp', 'gmpxx',
                                're2',
                                'boost_python',
                                'boost_system',
                                'boost_filesystem',
                                ],
                     sources=['fte/cDFA.cc'])

setup(name='Format-Transforming Encrypion (FTE)',
      version='0.2.0-alpha',
      description='FTE',
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://github.com/redjack/fte-proxy',
      packages=['fte',
                'fte.tests',
                ],
      scripts=['bin/fteproxy'],
      ext_modules=[fte_cDFA],
      )
