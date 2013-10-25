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

import fte.bit_ops


class InvalidKeyLengthError(Exception):

    """Raised when the input key length is not the correct size.
    """
    pass


class PlaintextTypeError(Exception):

    """Raised when the plaintext input to encrypt is not a string.
    """
    pass


class CiphertextTypeError(Exception):

    """Raised when the ciphertext input to decrypt is not a string.
    """
    pass


class RecoverableDecryptionError(Exception):

    """Raised when a non-fatal decryption error occurs, such as attempting to decrypt a substring of a valid ciphertext.
    """
    pass


class UnrecoverableDecryptionError(Exception):

    """Raised when a fatal decryption error occurs, such as an invalid MAC.
    """
    pass


class Encrypter(object):

    """On initialization, accepts optional keys ``K1`` and ``K2`` which much be exactly 16 bytes each.
    Object is a stateless encryption scheme with ``encrypt`` and ``decrypt`` functions.
    See [missing reference] for a description of the scheme.
    
    If ``K1`` is not specified, its default value is ``0xffffffffffffffffffffffffffffffff``.
    If ``K2`` is not specified, its default value is ``0x00000000000000000000000000000000``.
    """

    _MAC_LENGTH = AES.block_size
    _IV_LENGTH = 7
    _MSG_COUNTER_LENGTH = 8
    _CTXT_EXPANSION = 1 + _IV_LENGTH + _MSG_COUNTER_LENGTH + _MAC_LENGTH

    def __init__(self, K1=None, K2=None):

        if K1 is not None:
            is_correct_length = (len(K1) == AES.block_size)
            if not is_correct_length:
                raise InvalidKeyLengthError(
                    'K1 must be exactly 16 bytes long.')

        if K2 is not None:
            is_correct_length = (len(K2) == AES.block_size)
            if not is_correct_length:
                raise InvalidKeyLengthError(
                    'K2 must be exactly 16 bytes long.')

        self.K1 = K1 if K1 else '\xFF' * AES.block_size
        self.K2 = K2 if K2 else '\x00' * AES.block_size

        self._ecb_enc_K1 = AES.new(self.K1, AES.MODE_ECB)
        self._ecb_enc_K2 = AES.new(self.K2, AES.MODE_ECB)

    def encrypt(self, plaintext):
        """Given ``plaintext``, returns a ``ciphertext`` encrypted with an authentiated-encryption scheme, using the keys specified in ``__init__``.
        Ciphertext expansion is deterministic, the ouput ciphertext is always 42 bytes longer than the input ``plaintext``.
        The input ``plaintext`` can be ``''``.
    
        Raises ``PlaintextTypeError`` if input plaintext is not a string.
        """

        if not isinstance(plaintext, str):
            raise PlaintextTypeError("Input plaintext is not of type string")

        iv_bytes = fte.bit_ops.random_bytes(Encrypter._IV_LENGTH)
        iv1_bytes = '\x01' + iv_bytes
        iv2_bytes = '\x02' + iv_bytes

        W1 = iv1_bytes
        W1 += fte.bit_ops.long_to_bytes(
            len(plaintext), Encrypter._MSG_COUNTER_LENGTH)
        W1 = self._ecb_enc_K1.encrypt(W1)

        counter_length_in_bits = AES.block_size * 8
        counter_val = fte.bit_ops.bytes_to_long(iv2_bytes)
        counter = Counter.new(
            counter_length_in_bits, initial_value=counter_val)
        ctr_enc = AES.new(key=self.K1,
                          mode=AES.MODE_CTR,
                          IV=iv2_bytes,
                          counter=counter)
        W2 = ctr_enc.encrypt(plaintext)

        mac = HMAC.new(self.K2, W1 + W2, SHA512)
        T = mac.digest()
        T = T[:Encrypter._MAC_LENGTH]

        ciphertext = W1 + W2 + T

        return ciphertext

    def decrypt(self, ciphertext):
        """Given ``ciphertext`` returns a ``plaintext`` decrypted using the keys specified in ``__init__``.
        
        Raises ``CiphertextTypeError`` if the input ``ciphertext`` is not a string.
        Raises ``RecoverableDecryptionError`` if the input ``ciphertext`` has a non-negative message length greater than the ciphertext length.
        Raises ``UnrecoverableDecryptionError`` if invalid padding is detected, or the the MAC is invalid.
        """

        if not isinstance(ciphertext, str):
            raise CiphertextTypeError("Input ciphertext is not of type string")
        
        plaintext_length = self.getPlaintextLen(ciphertext)
        ciphertext_length = self.getCiphertextLen(ciphertext)
        ciphertext_complete = (len(ciphertext) >= ciphertext_length)
        if ciphertext_complete is False:
            raise RecoverableDecryptionError('Incomplete ciphertext.')

        ciphertext = ciphertext[:ciphertext_length]

        W1_start = 0
        W1_end = AES.block_size
        W1 = ciphertext[W1_start:W1_end]

        W2_start = AES.block_size
        W2_end = AES.block_size + plaintext_length
        W2 = ciphertext[W2_start:W2_end]

        T_start = AES.block_size + plaintext_length
        T_end = AES.block_size + plaintext_length + Encrypter._MAC_LENGTH
        T_expected = ciphertext[T_start:T_end]

        mac = HMAC.new(self.K2, W1 + W2, SHA512)
        T_actual = mac.digest()[:Encrypter._MAC_LENGTH]
        if T_expected != T_actual:
            raise UnrecoverableDecryptionError('Failed to verify MAC.')

        iv2_bytes = '\x02' + self._ecb_enc_K1.decrypt(W1)[1:8]
        counter_val = fte.bit_ops.bytes_to_long(iv2_bytes)
        counter_length_in_bits = AES.block_size * 8
        counter = Counter.new(
            counter_length_in_bits, initial_value=counter_val)
        ctr_enc = AES.new(key=self.K1,
                          mode=AES.MODE_CTR,
                          IV=iv2_bytes,
                          counter=counter)
        plaintext = ctr_enc.decrypt(W2)

        return plaintext

    def getCiphertextLen(self, ciphertext):
        """Given a ``ciphertext`` with a valid header, returns the length of the ciphertext inclusive of ciphertext expansion.
        """

        plaintext_length = self.getPlaintextLen(ciphertext)
        ciphertext_length = plaintext_length + Encrypter._CTXT_EXPANSION
        return ciphertext_length

    def getPlaintextLen(self, ciphertext):
        """Given a ``ciphertext`` with a valid header, returns the length of the plaintext payload.
        """
        
        completeCiphertextHeader = (len(ciphertext) >= 16)
        if completeCiphertextHeader is False:
            raise RecoverableDecryptionError('Incomplete ciphertext header.')

        ciphertext_header = ciphertext[:16]
        L = self._ecb_enc_K1.decrypt(ciphertext_header)

        padding_expected = '\x00\x00\x00\x00'
        padding_actual =L[-8:-4] 
        validPadding = (padding_actual == padding_expected)
        if validPadding is False:
            raise UnrecoverableDecryptionError('Invalid padding: ' + padding_actual)

        message_length = fte.bit_ops.bytes_to_long(L[-8:])

        msgLenNonNegative = (message_length >= 0)
        if msgLenNonNegative is False:
            raise UnrecoverableDecryptionError('Negative message length.')

        return message_length
