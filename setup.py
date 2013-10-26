#!/usr/bin/env python

from distutils.core import setup
from distutils.core import Extension

fte_cDFA = Extension('fte.cDFA',
                     include_dirs=['fte',
                                   'third-party/re2'],
                     library_dirs=['third-party/re2/obj'],
                     extra_compile_args=['-O3',
                                         '-fstack-protector-all',
                                         '-D_FORTIFY_SOURCE',
                                         '-fPIE',
                                        ],
                     extra_link_args=['-static'],
                     libraries=['gmp', 'gmpxx','re2',
                                'boost_python',
                                'boost_system',
                                'boost_filesystem',
                                ],
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
