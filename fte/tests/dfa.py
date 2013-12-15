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

import fte.dfa

NUM_TRIALS = 2 ** 10

MAX_LEN = 512
_regexs = [
    '^\C+$',
    '^(0|1)+$',
    '^(A|B)+$',
    '^(acat|adog)+$',
]


class TestDFA(unittest.TestCase):

    def testUnrankRank(self):
        for regex in _regexs:
            dfa = fte.dfa.from_regex(regex, MAX_LEN)
            for i in range(NUM_TRIALS):
                N = random.randint(0, (1 << dfa.getCapacity()))
                X = dfa.unrank(N)
                M = dfa.rank(X)
                self.assertEquals(N, M)

    def testUnrank1(self):
        dfa = fte.dfa.from_regex("^TESTTEST$", 8)
        self.assertEquals(dfa.unrank(0), "TESTTEST")
        try:
            dfa.unrank(1)
            self.fail(
                "IntegerOutOfRangeException not thrown when unranking out-of-bounds int")
        except fte.dfa.IntegerOutOfRangeException:
            pass

if __name__ == '__main__':
    unittest.main()
