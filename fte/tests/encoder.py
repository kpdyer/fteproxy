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
import sys
import fte.conf
import fte.encoder
import fte.cCfg
START = 0
ITERATIONS = 1024
STEP = 128


class TestCFGBase(unittest.TestCase):

    def testCFGEncoderRequest(self):
        for language in ['pet-intersection-response']:
            sys.stdout.write(str([language]))
            sys.stdout.flush()
            encoder = fte.encoder.Regexencoder(language)
            self.doTestEncoder(language, encoder)

    def doTestEncoder(self, language, encoder):
        for i in range(1024):
            partition = random.choice(encoder.getPartitions())
            N = encoder.getNextTemplateCapacity(partition, 0)
            C = random.randint(0, (1 << N) - 1)
            X = encoder.encode(N, C, partition)
            _partition = encoder.determinePartition(X[0])
            D = encoder.decode(X[0], _partition)
            self.assertEquals(C, D[1], language)


if __name__ == '__main__':
    unittest.main()