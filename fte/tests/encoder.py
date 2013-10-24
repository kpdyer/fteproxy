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

import fte.encoder
import fte.bit_ops
import fte.defs

class TestEncoders(unittest.TestCase):

    def testRegexEncoderRequest(self):
        definitions = fte.defs.load_definitions()
        for language in definitions.keys():
            encoder = fte.encoder.RegexEncoder(language)
            self.doTestEncoder(encoder, 0.5)
            self.doTestEncoder(encoder, 1)
            self.doTestEncoder(encoder, 2)
            self.doTestEncoder(encoder, 4)

    def doTestEncoder(self, encoder, factor = 1):
        for i in range(2 ** 7):
            N = int(encoder.getCapacity() * factor)
            C = random.randint(0, (1 << N) - 1)
            C = fte.bit_ops.long_to_bytes(C)
            X = encoder.encode(C)
            D = encoder.decode(X)
            self.assertEquals(C, D)

    #def testIntersection(self):
    #    for protocol in ['http', 'ssh', 'smb']:
    #        for direction in ['request', 'response']:
    #            intersection_language = 'intersection-' + protocol \
    #                + '-' + direction
    #            intersection_encoder = \
    #                fte.encoder.RegexEncoder(intersection_language)
    #            for classifier in ['appid', 'yaf1', 'yaf2', 'l7']:
    #                language = classifier + '-' + protocol + '-' \
    #                    + direction
    #                encoder = fte.encoder.RegexEncoder(language)
    #                for i in range(32):
    #                    N = intersection_encoder.getCapacity()
    #                    C = random.randint(0, (1 << N) - 1)
    #                    C = fte.bit_ops.long_to_bytes(C)
    #                    X = intersection_encoder.encode(C)
    #                    try:
    #                        encoder.decode(X)
    #                    except:
    #                        assert False, (intersection_language,
    #                                       language, X)


if __name__ == '__main__':
    unittest.main()
