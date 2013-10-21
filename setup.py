#!/usr/bin/env python

from distutils.core import setup
from distutils.core import Extension

fte_regex = Extension('fte.regex',
                       include_dirs=['fte'],
                       libraries=['gmp',
                                  'boost_python',
                                  'boost_system'],
                       sources=['fte/regex.cc'])

setup(name='Format-Transforming Encrypion (FTE)',
      version='0.2.0-alpha',
      description='FTE',
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://github.com/redjack/fte-proxy',
      packages=['fte',
                'dfas',
                'fte.tests',
                ],
      scripts=['bin/fte_proxy',
               'bin/dfa_intersect',
               'bin/regex2dfa'],
      ext_modules=[fte_regex],
      package_data={'dfas': ['*.dfa', 'dfas/*.dfa']}
      )
