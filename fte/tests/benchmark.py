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
import time
import fte.markov
import fte.encoder


class TestPerformance(unittest.TestCase):

    def doTestEncoder(
        self,
        language,
        encoder,
        model,
    ):
        capacity = 0
        i = 0
        while True:
            i += 1
            try:
                partition = model.transition()
            except:
                model.reset()
                partition = model.transition()
            N = encoder.getNextTemplateCapacity(partition)
            capacity += N
            C = random.randint(0, (1 << N) - 1)
            start = time.time()
            X = encoder.encode(N, C, partition)
            print (
                'encode',
                i,
                language,
                time.time() - start,
                partition,
                N,
            )
            start = time.time()
            _partition = encoder.determinePartition(X[0])
            self.assertEquals(partition, _partition)
            try:
                D = encoder.decode(X[0], _partition)
                self.assertEquals(C, D[1], language)
            except:
                with open('samples/' + str(i) + '.html', 'w') as f:
                    f.write(X[0])
                with open('samples/' + str(i) + '.capacity', 'w') as f:
                    f.write(str(N))
            print ('decode', language, time.time() - start)
        print ('avg. capacity', 1.0 * capacity / 1024)

    def testCFGEncoderRequest(self):
        for language in ['http_payload']:
            model = fte.markov.MarkovModel(language)
            encoder = fte.encoder.CFGEncoder(language)
            sys.stdout.write(str([language]))
            sys.stdout.flush()
            self.doTestEncoder(language, encoder, model)


if __name__ == '__main__':
    unittest.main()