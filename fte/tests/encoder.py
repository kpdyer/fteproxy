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

import unittest
import random

import fte.encoder
import fte.bit_ops
import fte.defs


NUM_TRIALS = 2 ** 12


class TestEncoders(unittest.TestCase):

    def testRegexEncoderRequest(self):
        definitions = fte.defs.load_definitions()
        for language in definitions.keys():
            regex = fte.defs.getRegex(language)
            fixed_slice = fte.defs.getFixedSlice(language)
            encoder = fte.encoder.RegexEncoder(regex, fixed_slice)
            self.doTestEncoder(encoder, 0.5)
            self.doTestEncoder(encoder, 1)
            self.doTestEncoder(encoder, 2)
            self.doTestEncoder(encoder, 4)
            self.doTestEncoder(encoder, 8)
            self.doTestEncoder(encoder, 16)

    def doTestEncoder(self, encoder, factor=1):
        for i in range(NUM_TRIALS):
            N = int(encoder.getCapacity() * factor)
            C = random.randint(0, (1 << N) - 1)
            C = fte.bit_ops.long_to_bytes(C)
            X = encoder.encode(C)
            D = encoder.decode(X)
            self.assertEquals(C, D)
