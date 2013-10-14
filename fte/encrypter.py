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

import random
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA512
from Crypto.Util import Counter
import fte.bit_ops


class DecryptionFailureException(Exception):

    pass


class CovertextHeaderDecryptionFailureException(Exception):

    pass


class UnrecoverableDecryptionFailureException(Exception):

    pass


class NegotiateExecption(Exception):

    data = ''


class NegotiateAcknowledgeExecption(Exception):

    data = ''


class Encrypter(object):

    MAC_SIZE = 8
    MSG_RELAY = '\x01'
    MSG_NEGOTIATE = '\x02'
    MSG_NEGOTIATE_ACK = '\x03'
    CTXT_EXPANSION_BITS = 336
    CTXT_EXPANSION_BYTES = CTXT_EXPANSION_BITS / 8

    def __init__(self, K1=None, K2=None):
        self.K1 = K1 if K1 else '\xFF' * 16
        self.K2 = K2 if K2 else '\x00' * 16

    def encrypt(self, M, messageType=MSG_RELAY):
        ecb_enc = AES.new(self.K1, AES.MODE_ECB)
        fte.logger.performance('encrypt', 'start')
        iv = fte.bit_ops.random_bytes(16)
        ctr_val = random.randint(0, (1 << 128) - 1)
        ctr = Counter.new(128, initial_value=ctr_val)
        ctr_enc = AES.new(self.K1, AES.MODE_CTR, iv,
                          counter=ctr)
        Z_plaintext = fte.bit_ops.long_to_bytes(ctr_val, 16)
        Z = ecb_enc.encrypt(Z_plaintext)
        M = messageType + M
        Y = ctr_enc.encrypt(M)
        mac = HMAC.new(self.K2, Z + Y, SHA512)
        T = mac.digest()[-Encrypter.MAC_SIZE:]
        L_plaintext = iv[-8:]
        L_plaintext += fte.bit_ops.long_to_bytes(len(Y), 8)
        L = ecb_enc.encrypt(L_plaintext)
        W = '\x01' + L + Y + Z + T
        retval = fte.bit_ops.bytes_to_long(W)
        fte.logger.performance('encrypt', 'stop')
        return retval

    def decrypt(self, highestBit, W):
        ecb_enc = AES.new(self.K1, AES.MODE_ECB)
        fte.logger.performance('decrypt', 'start')
        if not W:
            raise DecryptionFailureException('W is empty.')
        L = self.getMessageLen(highestBit, W)
        if L < 0 or highestBit < L * 8 + Encrypter.CTXT_EXPANSION_BITS \
                - 8:
            raise DecryptionFailureException(('Not enough data.',
                                              highestBit, L * 8 +
                                              Encrypter.CTXT_EXPANSION_BITS
                                              - 8))
        W <<= 8 - highestBit % 8
        W = fte.bit_ops.long_to_bytes(W)
        W = W[1:L + Encrypter.CTXT_EXPANSION_BYTES - 1]
        L = W[:16]
        Y = W[16:-(Encrypter.MAC_SIZE + 16)]
        Z = W[-(Encrypter.MAC_SIZE + 16):-Encrypter.MAC_SIZE]
        T = W[-Encrypter.MAC_SIZE:]
        TO_VERIFY = Z + Y
        mac = HMAC.new(self.K2, TO_VERIFY, SHA512)
        if T != mac.digest()[-Encrypter.MAC_SIZE:]:
            raise UnrecoverableDecryptionFailureException(('MAC fail.',
                                                           T, mac.digest()[-Encrypter.MAC_SIZE:]))
        S = ecb_enc.decrypt(Z)
        iv = ecb_enc.decrypt(L)
        ctr_val = fte.bit_ops.bytes_to_long(S)
        ctr_enc = AES.new(self.K1, AES.MODE_CTR, iv,
                          counter=Counter.new(128, initial_value=ctr_val))
        M = ctr_enc.decrypt(Y)
        if M[0] == Encrypter.MSG_NEGOTIATE:
            e = NegotiateExecption()
            e.data = M[1:]
            raise e
        elif M[0] == Encrypter.MSG_NEGOTIATE_ACK:
            e = NegotiateAcknowledgeExecption()
            e.data = M[1:]
            raise e
        fte.logger.performance('decrypt', 'stop')
        return M[1:]

    def getMessageLen(self, highestBit, W):
        ecb_enc = AES.new(self.K1, AES.MODE_ECB)
        fte.logger.performance('getMessageLen', 'start')
        if not W:
            raise DecryptionFailureException('W==0 or W==None or ...')
        if highestBit < 136:
            raise DecryptionFailureException('not enough bits :( , '
                                             + str(highestBit) + ' : ' + hex(W))
            return -1
        L = W >> highestBit - 136
        L &= 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        L = fte.bit_ops.long_to_bytes(L, 16)
        L = ecb_enc.decrypt(L)
        if L[-8:-4] != '\x00\x00\x00\x00':
            raise UnrecoverableDecryptionFailureException((
                'Invalid ciphertext header.', hex(W), L[:8]))
        fte.logger.performance('getMessageLen', 'stop')
        return fte.bit_ops.bytes_to_long(L[-8:])

    def encryptCovertextFooter(self, M):
        fte.logger.performance('encryptCovertextFooter', 'start')
        ecb_enc2 = AES.new(self.K2, AES.MODE_ECB)
        W = ecb_enc2.encrypt(M)
        fte.logger.performance('encryptCovertextFooter', 'stop')
        return W

    def decryptCovertextFooter(self, W):
        fte.logger.performance('decryptCovertextFooter', 'start')
        ecb_enc2 = AES.new(self.K2, AES.MODE_ECB)
        M = ecb_enc2.decrypt(W)
        fte.logger.performance('decryptCovertextFooter', 'stop')
        return M
