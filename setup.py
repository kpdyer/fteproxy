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
