#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Allow running fteproxy as a module: python -m fteproxy
"""

import sys

from fteproxy.cli import main

if __name__ == "__main__":
    sys.exit(main())
