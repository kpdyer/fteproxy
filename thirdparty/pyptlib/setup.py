#!/usr/bin/env python

import sys

from setuptools import setup, find_packages

setup(name='pyptlib',
      version='0.0.5',
      description='A python implementation of the Pluggable Transports for Circumvention specification for Tor',
      long_description='A python implementation of the Pluggable Transports for Circumvention specification for Tor',
      author='asn, Brandon Wiley',
      author_email='asn@torproject.org, brandon@blanu.net',
      classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: No Input/Output (Daemon)",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Topic :: Internet",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
      ],
      keywords='cryptography privacy internet',
      license='BSD',
      package_dir={'pyptlib': 'pyptlib'},
      packages=find_packages(exclude=['*.test']),
      test_suite='pyptlib.test',
     )
