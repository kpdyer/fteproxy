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


from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA512
from Crypto.Util import Counter
from Crypto import Random

import fte.bit_ops


class DecryptionFailureException(Exception):
    pass


class FatalDecryptionFailureException(Exception):
    pass


class Encrypter(object):
    MAC_LENGTH = AES.block_size
    IV_LENGTH = 7
    MSG_COUNTER_LENGTH = 8
    CTXT_EXPANSION = 42


    def __init__(self, K1=None, K2=None):
        self.K1 = K1 if K1 else '\xFF' * AES.block_size
        self.K2 = K2 if K2 else '\x00' * AES.block_size
        
        self._ecb_enc_K1 = AES.new(self.K1, AES.MODE_ECB)
        self._ecb_enc_K2 = AES.new(self.K2, AES.MODE_ECB)


    def encrypt(self, plaintext):
        iv_bytes = Random.new().read(Encrypter.IV_LENGTH)
        iv1_bytes = '\x01' + iv_bytes
        iv2_bytes = '\x02' + iv_bytes
        
        W1 = iv1_bytes
        W1 += fte.bit_ops.long_to_bytes(len(plaintext), Encrypter.MSG_COUNTER_LENGTH)
        W1 = self._ecb_enc_K1.encrypt(W1)
        
        counterLengthInBits = AES.block_size*8
        counter =Counter.new(counterLengthInBits, initial_value=0)
        ctr_enc = AES.new(key=self.K1,
                          mode=AES.MODE_CTR,
                          IV=iv2_bytes,
                          counter=counter)
        W2 = ctr_enc.encrypt(plaintext)
        
        mac = HMAC.new(self.K2, W1 + W2, SHA512)
        T = mac.digest()
        T = T[:Encrypter.MAC_LENGTH]
        
        ciphertext = W1 + W2 + T

        return ciphertext


    def decrypt(self, ciphertext):
        plaintextLength = self.getMessageLen(ciphertext)
        
        completeCiphertext = ((plaintextLength+Encrypter.CTXT_EXPANSION) >= len(ciphertext))
        
        if completeCiphertext is False:
            raise DecryptionFailureException('Incomplete ciphertext.')
        
        W1 = ciphertext[:AES.block_size]
        W2 = ciphertext[AES.block_size:AES.block_size+plaintextLength]
        T = ciphertext[AES.block_size+plaintextLength:AES.block_size+plaintextLength+Encrypter.MAC_LENGTH]
        
        mac = HMAC.new(self.K2, W1 + W2, SHA512)
        if T != mac.digest()[:Encrypter.MAC_LENGTH]:
            raise FatalDecryptionFailureException('Failed to verify MAC.')
        
        counter =Counter.new(AES.block_size*8, initial_value=0)
        iv2_bytes = self._ecb_enc_K1.decrypt(W1)[:8]
        ctr_enc = AES.new(key=self.K1,
                          mode=AES.MODE_CTR,
                          IV=iv2_bytes,
                          counter=counter)
        plaintext = ctr_enc.decrypt(W2)

        return plaintext


    def getMessageLen(self, ciphertext):
        completeCiphertextHeader = (len(ciphertext) >= 16)
        if completeCiphertextHeader is False:
            raise DecryptionFailureException('Incomplete ciphertext header.')
        
        ciphertext_header = ciphertext[:16]
        L = self._ecb_enc_K1.decrypt(ciphertext_header)
        
        validPadding = (L[-8:-4] == '\x00\x00\x00\x00')        
        if validPadding is False:
            raise DecryptionFailureException('Invalid padding.')

        messageLength = fte.bit_ops.bytes_to_long(L[-8:])
        
        msgLenNonNegative = (messageLength >= 0)
        if msgLenNonNegative is False:
            raise DecryptionFailureException('Negative message length.')

        return messageLength


    #def encryptCovertextFooter(self, plaintext):
    #    ciphertext = self._ecb_enc_K2.encrypt(plaintext)
    #    return ciphertext

    #def decryptCovertextFooter(self, ciphertext):
    #    plaintext = self._ecb_enc_K2.decrypt(ciphertext)
    #    return plaintext
