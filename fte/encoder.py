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
        fte.regex.loadLanguage(dfa_dir, self.regex_name, self.mtu)
        self.num_words = self.getNumWords()
        if self.num_words == 0:
            fte.regex.releaseLanguage(self.regex_name)
            raise LanguageIsEmptySetException()
        if self.fixed_slice == False:
            self.offset = 0
        else:
            self.fixed_slice = False
            self.offset = self.getNumWords()
            self.fixed_slice = True
            self.offset -= self.num_words

        self._capacity = -128
        self._capacity += int(math.floor(math.log(self.num_words, 2)))
        self.offset = gmpy.mpz(self.offset)
    

    def _getT(self, q, a):
        c = gmpy.mpz(0)
        fte.regex.getT(self.regex_name, c, int(q), a)
        return int(c)

    def _getNumStates(self):
        return fte.regex.getNumStates(self.regex_name)

    def _getNumWords(self, N=None):
        retval = 0
        if N == None:
            N = self.mtu
        q0 = fte.regex.getStart(self.regex_name)
        if self.fixed_slice:
            retval = gmpy.mpz(0)
            fte.regex.getT(self.regex_name, retval, q0, N)
        else:
            for i in range(N + 1):
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
        if self.fixed_slice:
            c -= self.offset
        return c

    def _unrank(self, c):
        c = gmpy.mpz(c)
        if self.fixed_slice:
            c += self.offset
        X = fte.regex.unrank(self.regex_name, c)
        if X == '':
            raise UnrankFailureException('Rank failed.')

        return str(X)

    def getCapacity(self, ):
        return self._capacity

    def encode(self, X):
        COVERTEXT_HEADER_LEN = 4
        maximumBytesToRank = int(math.floor(self.capacity / 8.0))

        msg_len = min(maximumBytesToRank - COVERTEXT_HEADER_LEN,
                      len(X))

        msg_len_header = fte.bit_ops.long_to_bytes(msg_len)
        msg_len_header = '\xFF' + \
            string.rjust(msg_len_header, COVERTEXT_HEADER_LEN - 1, '\x00')

        unrank_payload = msg_len_header + \
            X[:maximumBytesToRank - COVERTEXT_HEADER_LEN]
        unrank_payload = fte.bit_ops.bytes_to_long(unrank_payload)

        formatted_covertext_header = self.unrank(unrank_payload)
        unformatted_covertext_body = X[
            maximumBytesToRank - COVERTEXT_HEADER_LEN:]

        covertext = formatted_covertext_header + unformatted_covertext_body

        return covertext

    def decode(self, covertext):
        assert len(covertext) >= self.mtu, (len(covertext), self.mtu)
        unrank_payload = self.rank(covertext[:self.mtu])
        X = fte.bit_ops.long_to_bytes(unrank_payload)
        msg_len = fte.bit_ops.bytes_to_long(X[1:4])
        X = X[-msg_len:]
        X += covertext[self.mtu:]
        return X
