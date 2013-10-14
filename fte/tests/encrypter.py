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
import time
import fte.encrypter
KS_THRESHOLD = 0.01
HEX_CHARS = [fte.bit_ops.long_to_bytes(i, 1) for i in range(256)]
RV = []
for i in range(2048):
    RV.append(random.choice(HEX_CHARS))


class TestEncoders(unittest.TestCase):

    def setUp(self):
        self.encrypter = fte.encrypter.Encrypter()

    def testRandomnessNoOp(self):
        myChars = ''
        for i in range(128):
            C = self.encrypter.encrypt('')
            myChars += fte.bit_ops.long_to_bytes(C)
        chars = []
        for i in range(len(myChars)):
            chars.append(myChars[i])
        #(D, p) = stats.ks_2samp(chars, RV)
        #self.assertGreaterEqual(p, KS_THRESHOLD, p)

    def testEncryptNoOp(self):
        for i in range(1024):
            C = self.encrypter.encrypt('')
            lenC = fte.encrypter.Encrypter.CTXT_EXPANSION_BITS
            for j in range(10):
                self.assertEquals(self.encrypter.decrypt(lenC, C), '')

    def testEncryptDecrypt_1(self):
        myChars = ''
        for i in range(1024):
            P = 'X' * i
            C = self.encrypter.encrypt(P)
            self.assertNotEqual(C, P)
            lenC = fte.encrypter.Encrypter.CTXT_EXPANSION_BITS + len(P) \
                * 8
            for j in range(1):
                self.assertEquals(P, self.encrypter.decrypt(lenC, C))
            myChars += fte.bit_ops.long_to_bytes(C)
        chars = []
        for i in range(len(myChars)):
            chars.append(myChars[i])
        #(D, p) = stats.ks_2samp(chars, RV)
        #self.assertGreaterEqual(p, KS_THRESHOLD, p)

    def testEncryptDecrypt_2(self):
        for i in range(1024):
            P = '\x01' * 2 ** 15
            start = time.time()
            C = self.encrypter.encrypt(P)
            # print 'encrypt', time.time()-start
            self.assertNotEqual(C, P)
            lenC = fte.encrypter.Encrypter.CTXT_EXPANSION_BITS + len(P) \
                * 8
            for j in range(1):
                start = time.time()
                self.assertEquals(P, self.encrypter.decrypt(lenC, C))
                # print 'decrypt', time.time()-start

    def testEncryptDecryptCovertextFooter(self):
        myChars = ''
        for i in range(128):
            for j in range(128):
                M1 = random.randint(0, (1 << 128) - 1)
                M1 = fte.bit_ops.long_to_bytes(M1, 16)
                retval = self.encrypter.encryptCovertextFooter(M1)
                myChars += retval
                H_out = self.encrypter.decryptCovertextFooter(retval)
                self.assertEquals(M1, H_out)
        chars = []
        for i in range(len(myChars)):
            chars.append(myChars[i])
        #(D, p) = stats.ks_2samp(chars, RV)
        #self.assertGreaterEqual(p, KS_THRESHOLD, p)


if __name__ == '__main__':
    unittest.main()
