#!/usr/bin/env python3

from setuptools import setup
from setuptools import Extension

import glob
import sys
import os

with open('fteproxy/VERSION') as fh:
    FTEPROXY_RELEASE = fh.read().strip()

package_data_files = []
package_data_files += ['VERSION']
for filename in glob.glob('fteproxy/defs/*.json'):
    jsonFile = filename.split('/')[-1]
    package_data_files += ['defs/'+jsonFile]
package_data = {'fteproxy': package_data_files}

with open('README.md', encoding='utf-8') as file:
    long_description = file.read()

setup(name='fteproxy',
      long_description=long_description,
      long_description_content_type='text/markdown',
      test_suite='fteproxy.tests.suite',
      package_data=package_data,
      version=FTEPROXY_RELEASE,
      description='fteproxy',
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://fteproxy.org/',
      packages=['fteproxy', 'fteproxy.defs', 'fteproxy.tests'],
      install_requires=['fte'],
      python_requires='>=3.8',
      classifiers=[
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Programming Language :: Python :: 3.11',
          'Programming Language :: Python :: 3.12',
          'License :: OSI Approved :: MIT License',
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'Topic :: Security :: Cryptography',
          'Topic :: Internet :: Proxy Servers',
          'Operating System :: OS Independent',
      ],
      entry_points = {
        'console_scripts': [
            'fteproxy = fteproxy.cli:main'
            ]
        },
      )
