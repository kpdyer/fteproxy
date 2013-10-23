#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of FTE.
#
# FTE is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# FTE is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with FTE.  If not, see <http://www.gnu.org/licenses/>.

import gmpy
import binascii
import os


def random_bytes(N):
    return os.urandom(N)


def long_to_bytes(l, blocksize=0):
    retval = gmpy.mpz(l).digits(16)
    retval = '0' + retval if (len(retval) % 2) != 0 else retval
    retval = binascii.unhexlify(retval)
    if blocksize > 0 and len(retval) % blocksize != 0:
        retval = '\x00' * (blocksize - len(retval) % blocksize) + retval
    return retval


def bytes_to_long(s):
    s = '\x00' + s
    return gmpy.mpz(str(s)[::-1], 256)
