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

import string
import os
import socket
import math
import gmpy

import fte.conf
import fte.encrypter
import fte.bit_ops
import fte.regex


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


class RegexEncoder(object):
    COVERTEXT_HEADER_LEN = 4

    def __init__(self, regex_name):
        self.regex_name = regex_name
        self.mtu = fte.conf.getValue('languages.regex.' + regex_name
                                     + '.mtu')
        dfa_dir = fte.conf.getValue('general.dfa_dir')
        DFA_FILE = os.path.join(dfa_dir, regex_name + '.dfa')
        if not os.path.exists(DFA_FILE):
            raise LanguageDoesntExistException('DFA doesn\'t exist: '
                                               + DFA_FILE)
        
        fte.regex.loadLanguage(dfa_dir, self.regex_name, self.mtu)
        
        self._words_in_language = self._getNumWordsInLanguage()
        
        if self._words_in_language == 0:
            fte.regex.releaseLanguage(self.regex_name)
            raise LanguageIsEmptySetException()
        
        self.offset = self._words_in_language - self._getNumWordsInSlice(self.mtu)

        self._capacity = -128
        self._capacity += int(math.floor(math.log(self._words_in_language, 2)))
        
        self.offset = gmpy.mpz(self.offset)
    

    def _getT(self, q, a):
        c = gmpy.mpz(0)
        fte.regex.getT(self.regex_name, c, int(q), a)
        return int(c)

    def _getNumStates(self):
        return fte.regex.getNumStates(self.regex_name)

    def _getNumWordsInSlice(self, N):
        retval = 0
        q0 = fte.regex.getStart(self.regex_name)
        retval = gmpy.mpz(0)
        fte.regex.getT(self.regex_name, retval, q0, N)
        return int(retval)

    def _getNumWordsInLanguage(self):
        retval = 0
        q0 = fte.regex.getStart(self.regex_name)
        for i in range(self.mtu + 1):
            c = gmpy.mpz(0)
            fte.regex.getT(self.regex_name, c, q0, i)
            retval += c
        return int(retval)

    def _getStart(self):
        q0 = fte.regex.getStart(self.regex_name)
        return int(q0)

    def _delta(self, q, c):
        q_new = fte.regex.delta(self.regex_name, int(q), c)
        return q_new

    def _rank(self, X):
        c = gmpy.mpz(0)
        fte.regex.rank(self.regex_name, c, X)
        if c == -1:
            raise RankFailureException(('Rank failed.', X))
        c -= self.offset
        return c

    def _unrank(self, c):
        c = gmpy.mpz(c)
        c += self.offset
        X = fte.regex.unrank(self.regex_name, c)
        if X == '':
            raise UnrankFailureException('Rank failed.')

        return str(X)

    def getCapacity(self, ):
        return self._capacity

    def encode(self, X):
        if not isinstance(X, str):
            raise InvalidInputException('Input must be of type string.')
            
        maximumBytesToRank = int(math.floor(self._capacity / 8.0))

        msg_len = min(maximumBytesToRank - RegexEncoder.COVERTEXT_HEADER_LEN, len(X))

        msg_len_header = fte.bit_ops.long_to_bytes(msg_len)
        msg_len_header = '\xFF' + string.rjust(msg_len_header, RegexEncoder.COVERTEXT_HEADER_LEN - 1, '\x00')

        unrank_payload = msg_len_header + X[:maximumBytesToRank - RegexEncoder.COVERTEXT_HEADER_LEN]
        unrank_payload = fte.bit_ops.bytes_to_long(unrank_payload)

        formatted_covertext_header = self._unrank(unrank_payload)
        unformatted_covertext_body = X[maximumBytesToRank - RegexEncoder.COVERTEXT_HEADER_LEN:]

        covertext = formatted_covertext_header + unformatted_covertext_body

        return covertext

    def decode(self, covertext):
        if not isinstance(covertext, str):
            raise InvalidInputException('Input must be of type string.')
        
        assert len(covertext) >= self.mtu, (len(covertext), self.mtu)
        
        unrank_payload = self._rank(covertext[:self.mtu])
        X = fte.bit_ops.long_to_bytes(unrank_payload)
        msg_len = fte.bit_ops.bytes_to_long(X[1:4])
        X = X[-msg_len:] + covertext[self.mtu:]
        
        return X
