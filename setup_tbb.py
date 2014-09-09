#!/usr/bin/env python



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
          "includes": ["twisted", "pyptlib", "Crypto", "txsocksx", "parsley", "obfsproxy", "fte"],
      }
      },
      version=FTEPROXY_RELEASE,
      description='fteproxy',
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://github.com/kpdyer/fteproxy',
      packages=['fteproxy', 'fteproxy.defs', 'fteproxy.tests'],
      install_requires=['pyptlib', 'obfsproxy', 'twisted', 'fte']
      )
