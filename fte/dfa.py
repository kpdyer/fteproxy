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


import gmpy
import math
import string
import random

import fte.cDFA


class LanguageIsEmptySetException(Exception):

    pass


class UnrankFailureException(Exception):

    pass


class RankFailureException(Exception):

    pass


class DFA(object):

    def __init__(self, dfa, max_len):
        self._dfa = dfa
        self.max_len = max_len

        self._words_in_language = self._getNumWordsInLanguage()
        self._words_in_slice = self._getNumWordsInSlice(self.max_len)
        self._offset = self._words_in_language - self._words_in_slice
        self._offset = gmpy.mpz(self._offset)

        if self._words_in_slice == 0:
            #fte.cDFA.releaseLanguage(self._dfa_id)
            raise LanguageIsEmptySetException()

        self._capacity = -128
        self._capacity += int(math.floor(math.log(self._words_in_slice, 2)))


    def _getT(self, q, a):
        c = gmpy.mpz(0)
        self._dfa.getT(c, int(q), a)
        return int(c)

    def _getStart(self):
        q0 = self._dfa.getStart()
        return int(q0)

    def _getNumWordsInSlice(self, N):
        retval = 0
        q0 = self._getStart()
        retval = gmpy.mpz(0)
        retval = self._getT(q0, N)
        return int(retval)

    def _getNumWordsInLanguage(self):
        retval = 0
        q0 = self._getStart()
        for i in range(self.max_len + 1):
            c = self._getT(q0, i)
            retval += c
        return int(retval)

    def rank(self, X):
        c = gmpy.mpz(0)
        self._dfa.rank(c, X)

        if c == -1:
            raise RankFailureException(('Rank failed.', X))
        c -= self._offset
        return c

    def unrank(self, c):
        c = gmpy.mpz(c)
        c += self._offset
        X = self._dfa.unrank(c)
        if X == '':
            raise UnrankFailureException('Unank failed.')

        return str(X)

    def getCapacity(self):
        return self._capacity

    def _setATTFSTString(self, val):
        self._dfa_string = val

    def getATTFSTString(self):
        return self._dfa_string


def from_regex(regex, max_len):
    regex = str(regex)
    max_len = int(max_len)

    dfa = fte.cDFA.fromRegex(regex)
    dfa = fte.cDFA.minimize(dfa)
    dfa = dfa.strip()

    cDFA = fte.cDFA.DFA(dfa, max_len)
    retval = DFA(cDFA, max_len)
    retval._setATTFSTString(dfa)

    return retval
