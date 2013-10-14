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

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import random
import threading
import unittest
import copy
import fte.encoder
import fte.encrypter
import fte.record_layer
import fte.markov
START = 0
ITERATIONS = 2048
STEP = 64


class TestEncoders(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        encrypter = fte.encrypter.Encrypter()
        fte.conf.setValue('runtime.mode', 'client')
        fte.conf.setValue('runtime.state.message_token', 'client')
        self.recoder_layers_info = []
        self.record_layers_outgoing = []
        self.record_layers_incoming = []
        for languageA in fte.conf.getValue('languages.regex'):
            cfgse = fte.encoder.RegexEncoder(languageA)
            mm = fte.markov.MarkovModel('request-response',
                                        exceptionOnDeath=False)
            lock = threading.RLock()
            encoder = fte.record_layer.RecordLayerEncoder(0, lock,
                                                          encrypter, cfgse, copy.deepcopy(mm))
            decoder = fte.record_layer.RecordLayerDecoder(0, lock,
                                                          encrypter, cfgse, copy.deepcopy(mm))
            self.recoder_layers_info.append(languageA)
            self.record_layers_outgoing.append(encoder)
            self.record_layers_incoming.append(decoder)

    def testReclayer_basic(self):
        for i in range(len(self.record_layers_outgoing)):
            record_layer_outgoing = self.record_layers_outgoing[i]
            record_layer_incoming = self.record_layers_incoming[i]
            sys.stdout.write(str([self.recoder_layers_info[i]]))
            sys.stdout.flush()
            for j in range(START, ITERATIONS, STEP):
                P = 'X' * j + 'Y'
                record_layer_outgoing.push(P)
                while True:
                    try:
                        retval = record_layer_outgoing.pop()
                        record_layer_incoming.push(retval[0])
                        if retval[1] == False:
                            break
                    except fte.markov.DeadStateException:
                        record_layer_outgoing.model.reset()
                Y = ''
                while True:
                    try:
                        retval = record_layer_incoming.pop()
                    except fte.record_layer.PopFailedException, e:
                        print ('ppo', e.message)
                        break
                    Y += retval[0]
                    if retval[1] == False:
                        break
                self.assertEquals(P, Y, (self.recoder_layers_info[i],
                                  P, Y))

    def testReclayer_concat(self):
        for i in range(len(self.record_layers_outgoing)):
            record_layer_outgoing = self.record_layers_outgoing[i]
            record_layer_incoming = self.record_layers_incoming[i]
            sys.stdout.write(str([self.recoder_layers_info[i]]))
            sys.stdout.flush()
            for j in range(START, ITERATIONS, STEP):
                ptxt = ''
                X = ''
                P = 'X' * j + 'Y'
                ptxt += P
                record_layer_outgoing.push(P)
                while True:
                    try:
                        retval = record_layer_outgoing.pop()
                        X += retval[0]
                        if retval[1] == False:
                            break
                    except fte.markov.DeadStateException:
                        record_layer_outgoing.model.reset()
                record_layer_incoming.push(X)
                Y = ''
                while True:
                    try:
                        retval = record_layer_incoming.pop()
                    except Exception, e:
                        print e
                        break
                    Y += retval[0]
                    if retval[1] == False:
                        break
                self.assertEquals(ptxt, Y, self.recoder_layers_info[i])


if __name__ == '__main__':
    unittest.main()