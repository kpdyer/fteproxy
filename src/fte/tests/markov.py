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

# You should have received a copy of the GNU General Public License
# along with FTE.  If not, see <http://www.gnu.org/licenses/>.

#!/usr/bin/python
# -*- coding: utf-8 -*-
import unittest
import random
import fte.markov


class TestEncoders(unittest.TestCase):

    def testMarkov_basic(self):
        for language in fte.conf.getValue('formats'):
            n = random.randint(0, 2 ** 20)
            mm1 = fte.markov.MarkovModel(language)
            mm2 = fte.markov.MarkovModel(language)
            for i in range(20):
                try:
                    state1 = mm1.transition()
                except fte.markov.DeadStateException:
                    mm1.reset()
                    pass
                try:
                    state2 = mm2.transition()
                except fte.markov.DeadStateException:
                    mm2.reset()
                    pass
                self.assertEquals(mm1.state, mm2.state)


if __name__ == '__main__':
    unittest.main()