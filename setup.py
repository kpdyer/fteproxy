#!/usr/bin/env python

from distutils.core import setup
from distutils.core import Extension

fte_cRegex = Extension('fte.cRegex',
                       include_dirs=['fte'],
                       libraries=['gmp',
                                  'boost_python',
                                  'boost_system'],
                       sources=['fte/cRegex.cc'])

setup(name='Format-Transforming Encrypion (FTE)',
      version='0.2.0-alpha',
      description='FTE',
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://github.com/redjack/FTE',
      packages=['fte',
                'fte.dfas',
                'fte.tcp'],
      scripts=['bin/fte_proxy'],
      ext_modules=[fte_cRegex],
      package_data={'fte.dfas': ['*.dfa','fte/dfas/*.dfa']}
      )
