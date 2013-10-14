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

import unittest
import random
import fte.bit_ops


class TestEncoders(unittest.TestCase):

    def _testMSB(self):
        self.assertEquals(15, fte.bit_ops.msb(0xFF, 4))
        self.assertEquals(0xFFFFFFFFFFFFFFFF,
                          fte.bit_ops.msb(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
                                          4 * 16))
        self.assertEquals(15, fte.bit_ops.msb(0xFFFFFFFFFFFFFFFFF, 4))
        self.assertEquals(15, fte.bit_ops.msb(0xF0000000000000000, 4))

    def _testLSB(self):
        self.assertEquals(15, fte.bit_ops.lsb(0xFF, 4))
        self.assertEquals(0xFFFFFFFFFFFFFFFF,
                          fte.bit_ops.lsb(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
                                          4 * 16))
        self.assertEquals(15, fte.bit_ops.lsb(0xFFFFFFFFFFFFFFFFF, 4))
        self.assertEquals(15, fte.bit_ops.lsb(15, 4))

    def testLTB(self):
        self.assertEquals(fte.bit_ops.long_to_bytes(0xff), '\xFF')
        self.assertEquals(fte.bit_ops.bytes_to_long('\xFF'), 0xff)

    def testLTB2(self):
        for i in range(2 ** 10):
            N = random.randint(0, 1 << 1024)
            M = fte.bit_ops.long_to_bytes(N)
            M = fte.bit_ops.bytes_to_long(M)
            self.assertEquals(N, M)

    def testLTB3(self):
        for i in range(2 ** 10):
            N = random.randint(0, 1 << 1024)
            M = fte.bit_ops.long_to_bytes(N, 1024)
            self.assertEquals(1024, len(M))
            M = fte.bit_ops.bytes_to_long(M)
            self.assertEquals(N, M)


if __name__ == '__main__':
    unittest.main()