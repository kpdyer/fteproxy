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
import string
import random
import time
import sys
import os
import math
import gmpy
import fte.conf
import fte.encrypter
import fte.bit_ops
if fte.conf.getValue('modules.regex.enable'):
    import fte.cRegex
LOG_LEVEL = fte.conf.getValue('loglevel.fte.regex')
sys.path.append('..')

LOG_LEVEL = fte.conf.getValue('loglevel.fte.encoder')


class UnrankFailureException(Exception):

    pass


class RankFailureException(Exception):

    pass


class DecodeFailureException(Exception):

    pass


class InvalidInputException(Exception):

    pass


class LanguageDoesntExistException(Exception):

    pass


class LanguageIsEmptySetException(Exception):

    pass


class Encoder(object):

    def __init__(self, language):
        self.format_package = None

    def getPartitions(self):
        assert False

    def getNextTemplateCapacity(self, partition, minCapacity=None):
        assert False

    def determinePartition(self, msg):
        assert False

    def encode(
        self,
        msb,
        C,
        partition,
    ):
        assert False

    def decode(self, X, partition):
        assert False


class DummyEncoder(Encoder):

    def __init__(self, language):
        self.format_package = None
        self.capacity = 2 ** 15

    def getPartitions(self):
        return ['000']

    def getNextTemplateCapacity(self, partition, minCapacity=None):
        return self.capacity

    def determinePartition(self, msg):
        return '000'

    def encode(
        self,
        msb,
        C,
        partition,
    ):
        num_bytes = msb / 8
        frag = fte.bit_ops.long_to_bytes(C, num_bytes)
        assert len(frag) == msb / 8, (len(frag), msb / 8)
        return [frag, msb, '']

    def decode(self, X, partition):
        return [len(X) * 8, fte.bit_ops.bytes_to_long(X), '']


# We could just as welll deletc RegexEncoder and rename RegexEncoderObject to RegexEncoder.
# However, each time a RegexEncoder is created we don't want to want to recompute language-specific
# information such as buildTable. Hence, RegexEncoder is a facde that caches the RegexEncoderObject
# such that we only have one object per language.
_instance = {}


class RegexEncoder(object):

    def __new__(self, regex_name):
        global _instance
        if not _instance.get(regex_name):
            _instance[regex_name] = RegexEncoderObject(regex_name)
        return _instance[regex_name]


class RegexEncoderObject(Encoder):

    def __init__(self, regex_name):
        self.compound = False
        self.format_package = None
        self.mtu = fte.conf.getValue('languages.regex.' + regex_name
                                     + '.mtu')
        self.fixedLength = False
        self.regex_name = regex_name
        self.fixed_slice = fte.conf.getValue('languages.regex.'
                                             + regex_name + '.fixed_slice')
        dfa_dir = fte.conf.getValue('general.dfa_dir')
        DFA_FILE = os.path.join(dfa_dir, regex_name + '.dfa')
        if not os.path.exists(DFA_FILE):
            raise LanguageDoesntExistException('DFA doesn\'t exist: '
                                               + DFA_FILE)
        fte.cRegex.loadLanguage(dfa_dir, self.regex_name, self.mtu)
        self.num_words = self.getNumWords()
        if self.num_words == 0:
            fte.cRegex.releaseLanguage(self.regex_name)
            raise LanguageIsEmptySetException()
        if self.fixed_slice == False:
            self.offset = 0
        else:
            self.fixed_slice = False
            self.offset = self.getNumWords()
            self.fixed_slice = True
            self.offset -= self.num_words

        self.capacity = -128
        self.capacity += int(math.floor(math.log(self.num_words, 2)))
        self.offset = gmpy.mpz(self.offset)

    def getPartitions(self):
        return ['000']

    def determinePartition(self, msg):
        return self.regex_name

    def getNextTemplateCapacity(self, partition, minCapacity=None):
        return self.capacity

    def getT(self, q, a):
        c = gmpy.mpz(0)
        fte.cRegex.getT(self.regex_name, c, int(q), a)
        return int(c)

    def getNumStates(self):
        return fte.cRegex.getNumStates(self.regex_name)

    def getSizeOfT(self):
        return fte.cRegex.getSizeOfT(self.regex_name)

    def getNumWords(self, N=None):
        retval = 0
        if N == None:
            N = self.mtu
        q0 = fte.cRegex.getStart(self.regex_name)
        if self.fixed_slice:
            retval = gmpy.mpz(0)
            fte.cRegex.getT(self.regex_name, retval, q0, N)
        else:
            for i in range(N + 1):
                c = gmpy.mpz(0)
                fte.cRegex.getT(self.regex_name, c, q0, i)
                retval += c
        return int(retval)

    def getStart(self):
        q0 = fte.cRegex.getStart(self.regex_name)
        return int(q0)

    def delta(self, q, c):
        q_new = fte.cRegex.delta(self.regex_name, int(q), c)
        return q_new

    def rank(self, X):
        fte.logger.performance('rank', 'start')
        c = gmpy.mpz(0)
        fte.cRegex.rank(self.regex_name, c, X)
        if c == -1:
            raise RankFailureException(('Rank failed.', X))
        if self.fixed_slice:
            # c = gmpy.sub(c, self.offset)
            c -= self.offset
        fte.logger.performance('rank', 'stop')
        return c

    def unrank(self, c):
        fte.logger.performance('unrank', 'start')
        c = gmpy.mpz(c)
        if self.fixed_slice:
            # c = gmpy.add(self.offset, c)
            c += self.offset  # gmpy.add(self.offset, c)
        X = fte.cRegex.unrank(self.regex_name, c)
        if X == '':
            raise UnrankFailureException('Rank failed.')
        fte.logger.performance('unrank', 'stop')
        return str(X)

    def encode(
        self,
        msb,
        C,
        partition,
    ):
        TAIL = fte.conf.getValue('languages.regex.' + self.regex_name
                                 + '.allow_ae_bits')
        if msb <= self.capacity:
            TAIL = False
            remainder = 0
        else:
            (C, remainder) = fte.bit_ops.peel_off(self.capacity, msb
                                                  - self.capacity, C)
        if TAIL:
            covertext_ae_bytes = fte.bit_ops.long_to_bytes(remainder)
        else:
            covertext_ae_bytes = ''
        if TAIL:
            covertext_header = msb - self.capacity
            covertext_header = \
                fte.bit_ops.long_to_bytes(covertext_header)
            covertext_header = string.rjust(covertext_header, 8, '\x00')
            covertext_header = fte.bit_ops.random_bytes(8) + covertext_header
        else:
            covertext_header = '\x00\x00\x00\x00\x00\x00\x00\x00'
            covertext_header = fte.bit_ops.random_bytes(8) + covertext_header
        covertext_header = string.rjust(covertext_header, 16, '\x00')
        if TAIL:
            num_ae_bits = msb - self.capacity
            num_ae_bytes = int(math.ceil(num_ae_bits / 8.0))
            covertext_ae_bytes = string.rjust(covertext_ae_bytes,
                                              num_ae_bytes, '\x00')
        else:
            num_ae_bits = 0
            num_ae_bytes = 0
        covertext_header = \
            fte.encrypter.Encrypter().encryptCovertextFooter(covertext_header)
        covertext_header = fte.bit_ops.bytes_to_long(covertext_header)
        C += covertext_header << self.capacity
        covertext = self.unrank(C)
        if self.fixed_slice:
            assert len(covertext) == self.mtu
        if TAIL:
            covertext += covertext_ae_bytes
            bits_encoded = msb
            remainder = 0
        else:
            bits_encoded = self.capacity
        return [covertext, bits_encoded, remainder]

    def getMsgLen(self, X, partition):
        if len(X) < self.mtu:
            raise DecodeFailureException()
        try:
            C = self.rank(X[:self.mtu])
        except RankFailureException, e:
            raise DecodeFailureException('rank')
        (covertext_header, remainder) = fte.bit_ops.peel_off(128,
                                                             self.capacity, C)
        covertext_header = fte.bit_ops.long_to_bytes(covertext_header,
                                                     16)
        if len(covertext_header) != 16:
            raise DecodeFailureException('header')
        covertext_header = \
            fte.encrypter.Encrypter().decryptCovertextFooter(covertext_header)
        num_ae_bits = fte.bit_ops.bytes_to_long(covertext_header[-8:])
        num_ae_bytes = int(math.ceil(num_ae_bits / 8.0))
        if num_ae_bytes > fte.conf.getValue('runtime.fte.record_layer.max_cell_size'):
            raise DecodeFailureException('header')
        return (self.mtu + num_ae_bytes)

    def decode(self, X, partition):
        if len(X) < self.mtu:
            raise DecodeFailureException()
        try:
            C = self.rank(X[:self.mtu])
        except RankFailureException, e:
            raise DecodeFailureException('rank')
        (covertext_header, remainder) = fte.bit_ops.peel_off(128,
                                                             self.capacity, C)
        covertext_header = fte.bit_ops.long_to_bytes(covertext_header,
                                                     16)
        if len(covertext_header) != 16:
            raise DecodeFailureException('header')

        covertext_header = \
            fte.encrypter.Encrypter().decryptCovertextFooter(covertext_header)
        num_ae_bits = fte.bit_ops.bytes_to_long(covertext_header[-8:])
        num_ae_bytes = int(math.ceil(num_ae_bits / 8.0))
        if num_ae_bytes > fte.conf.getValue('runtime.fte.record_layer.max_cell_size'):
            raise DecodeFailureException('header')

        if len(X) < (self.mtu + num_ae_bytes):
            raise DecodeFailureException('ae bytes 2 : ' + str(len(X))
                                         + ',' + str(self.mtu + num_ae_bytes))
        retval = remainder
        if num_ae_bits > 0:
            retval <<= num_ae_bits
            retval += fte.bit_ops.bytes_to_long(X[self.mtu:self.mtu
                                                  + num_ae_bytes])
        return [self.capacity + num_ae_bits, long(retval), X[self.mtu
                + num_ae_bytes:]]