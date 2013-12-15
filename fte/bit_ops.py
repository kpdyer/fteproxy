#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of fteproxy.
#
# fteproxy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# fteproxy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with fteproxy.  If not, see <http://www.gnu.org/licenses/>.

try:
    import gmpy2 as gmpy
except ImportError:
    import gmpy

import binascii
import os


def random_bytes(N):
    """Given an input integer ``N``, ``random_bytes`` returns a string of exactly ``N`` uniformly-random bytes.
    Calls ``os.urandom`` to get the random bytes.
    """
    return os.urandom(N)


def long_to_bytes(N, blocksize=1):
    """Given an input integer ``N``, ``long_to_bytes`` returns the representation of ``N`` in bytes.
    If ``blocksize`` is greater than ``1`` then the output string will be right justified and then padded with zero-bytes,
    such that the return values length is a multiple of ``blocksize``.
    """

    bytestring = gmpy.mpz(N).digits(16)
    bytestring = bytestring[2:] if bytestring.startswith('0x') else bytestring
    bytestring = '0' + bytestring if (len(bytestring) % 2) != 0 else bytestring
    bytestring = binascii.unhexlify(bytestring)

    if blocksize > 0 and len(bytestring) % blocksize != 0:
        bytestring = '\x00' * \
            (blocksize - (len(bytestring) % blocksize)) + bytestring

    return bytestring


def bytes_to_long(bytestring):
    """Given a ``bytestring`` returns its integer representation ``N``.
    """

    bytestring = '\x00' + bytestring
    N = gmpy.mpz(str(bytestring)[::-1], 256)
    return N
