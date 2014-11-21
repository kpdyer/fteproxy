#!/usr/bin/env python
# -*- coding: utf-8 -*-



import unittest

import fteproxy.record_layer
import fteproxy.regex2dfa

import fte.encoder

START = 0
ITERATIONS = 2048
STEP = 64


class Tests(unittest.TestCase):

    @classmethod
    def setUp(self):
        fteproxy.conf.setValue('runtime.mode', 'client')
        self.record_layers_info = []
        self.record_layers_outgoing = []
        self.record_layers_incoming = []
        definitions = fteproxy.defs.load_definitions()
        for language in definitions.keys():
            regex = fteproxy.defs.getRegex(language)
            fixed_slice = fteproxy.defs.getFixedSlice(language)
            regex_encoder = fte.encoder.DfaEncoder(fteproxy.regex2dfa.regex2dfa(regex), fixed_slice)
            encoder = fteproxy.record_layer.Encoder(
                encoder=regex_encoder)
            decoder = fteproxy.record_layer.Decoder(
                decoder=regex_encoder)
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


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(Tests))
    return suite
