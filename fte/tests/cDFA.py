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

import fte.cDFA


class TestcDFA(unittest.TestCase):

    def testMakeDFA(self):
        for i in range(1, 6):
            with open('fte/tests/dfas/test' + str(i) + '.regex') as fh:
                regex = fh.read()

            with open('fte/tests/dfas/test' + str(i) + '.dfa') as fh:
                expected_dfa = fh.read()

            dfa = fte.cDFA.fromRegex(regex)
            dfa = fte.cDFA.minimize(dfa)
            dfa = dfa.strip()

            self.assertEquals(dfa, expected_dfa)

if __name__ == '__main__':
    unittest.main()
