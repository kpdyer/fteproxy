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

import sys
import threading
import unittest


import fte.encoder
import fte.encrypter
import fte.record_layer


START = 0
ITERATIONS = 2048
STEP = 64


class TestEncoders(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        encrypter = fte.encrypter.Encrypter()
        fte.conf.setValue('runtime.mode', 'client')
        self.record_layers_info = []
        self.record_layers_outgoing = []
        self.record_layers_incoming = []
        definitions = fte.defs.load_definitions()
        for language in definitions.keys():
            regex = fte.defs.getRegex(language)
            max_len = fte.defs.getMaxLen(language)
            regex_encoder = fte.encoder.RegexEncoder(regex, max_len)
            encoder = fte.record_layer.Encoder(
                encrypter=encrypter, encoder=regex_encoder)
            decoder = fte.record_layer.Decoder(
                decrypter=encrypter, decoder=regex_encoder)
            self.record_layers_info.append(language)
            self.record_layers_outgoing.append(encoder)
            self.record_layers_incoming.append(decoder)

    def testReclayer_basic(self):
        for i in range(len(self.record_layers_outgoing)):
            record_layer_outgoing = self.record_layers_outgoing[i]
            record_layer_incoming = self.record_layers_incoming[i]
            for j in range(START, ITERATIONS, STEP):
                P = 'X' * j + 'Y'
                record_layer_outgoing.push(P)
                while True:
                    data = record_layer_outgoing.pop()
                    if not data:
                        break
                    record_layer_incoming.push(data)
                Y = ''
                while True:
                    data = record_layer_incoming.pop()
                    if not data:
                        break
                    Y += data
                self.assertEquals(P, Y, (self.record_layers_info[i],
                                  P, Y))

    def testReclayer_concat(self):
        for i in range(len(self.record_layers_outgoing)):
            record_layer_outgoing = self.record_layers_outgoing[i]
            record_layer_incoming = self.record_layers_incoming[i]
            for j in range(START, ITERATIONS, STEP):
                ptxt = ''
                X = ''
                P = 'X' * j + 'Y'
                ptxt += P
                record_layer_outgoing.push(P)
                while True:
                    data = record_layer_outgoing.pop()
                    if not data:
                        break
                    X += data
                record_layer_incoming.push(X)
                Y = ''
                while True:
                    data = record_layer_incoming.pop()
                    if not data:
                        break
                    Y += data
                self.assertEquals(ptxt, Y, self.record_layers_info[i])


if __name__ == '__main__':
    unittest.main()
