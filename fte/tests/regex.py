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
import sys
import time
import random

import fte.encoder


class TestEncoders(unittest.TestCase):

    def testRegexEncoderRequest(self):
        for language in fte.conf.getValue('languages.regex'):
            sys.stdout.write(str([language]))
            sys.stdout.flush()
            encoder = fte.encoder.RegexEncoder(language)
            self.doTestEncoder(language, encoder)

    def doTestEncoder(self, language, encoder):
        if 'learned' in language:
            return
        for i in range(2 ** 7):
            partition = random.choice(encoder.getPartitions())
            N = encoder.getNextTemplateCapacity(partition, 0)
            # N *= random.choice(range(10))
            C = random.randint(0, (1 << N) - 1)
            start = time.time()
            X = encoder.encode(N, C, partition)
            # print [language,'encode',N,time.time()-start]
            _partition = encoder.determinePartition(X[0])
            start = time.time()
            D = encoder.decode(X[0], _partition)
            # print [language,'decode',N,time.time()-start]
            self.assertEquals(C, D[1], language)
        for i in range(2 ** 7):
            if fte.conf.getValue('languages.regex.' + language
                                 + '.allow_ae_bits'):
                partition = random.choice(encoder.getPartitions())
                N = fte.conf.getValue(
                    'runtime.fte.record_layer.max_cell_size') * 8
                C = random.randint(0, (1 << N) - 1)
                start = time.time()
                X = encoder.encode(N, C, partition)
                #print [language, 'encode', N, time.time() - start]
                _partition = encoder.determinePartition(X[0])
                start = time.time()
                D = encoder.decode(X[0], _partition)
                #print [language, 'decode', N, time.time() - start]
                self.assertEquals(C, D[1], language)

    def testIntersection(self):
        for protocol in ['http', 'ssh', 'smb']:
            for direction in ['request', 'response']:
                intersection_language = 'intersection-' + protocol \
                    + '-' + direction
                intersection_encoder = \
                    fte.encoder.RegexEncoder(intersection_language)
                for classifier in ['appid', 'yaf1', 'yaf2', 'l7']:
                    language = classifier + '-' + protocol + '-' \
                        + direction
                    encoder = fte.encoder.RegexEncoder(language)
                    for i in range(32):
                        C = random.randint(0,
                                           intersection_encoder.getNumWords())
                        # start = time.time()
                        X = intersection_encoder.unrank(C)
                        # print 'unrank', time.time()-start
                        try:
                            # start = time.time()
                            encoder.rank(X)
                            # print 'rank', time.time()-start
                        except fte.encoder.RankFailureException, e:
                            assert False, (intersection_language,
                                           language, X)


if __name__ == '__main__':
    unittest.main()
