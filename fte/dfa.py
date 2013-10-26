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

import time
import gmpy
import math

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

        self._words_in_language = self._dfa.getNumWordsInLanguage(0, self.max_len)
        self._words_in_slice = self._dfa.getNumWordsInLanguage(self.max_len, self.max_len)
        
        self._offset = self._words_in_language - self._words_in_slice
        self._offset = gmpy.mpz(self._offset)

        if self._words_in_slice == 0:
            raise LanguageIsEmptySetException()

        self._capacity = int(math.floor(math.log(self._words_in_slice, 2)))

    def rank(self, X):
        c = gmpy.mpz(0)
        self._dfa.rank(X, c)
        c -= self._offset
        return c

    def unrank(self, c):
        c = gmpy.mpz(c)
        c += self._offset
        X = self._dfa.unrank(c)
        return str(X)

    def getCapacity(self):
        return self._capacity


def from_regex(regex, max_len):
    regex = str(regex)
    max_len = int(max_len)

    att_fst = fte.cDFA.attFstFromRegex(regex)
    att_fst = fte.cDFA.attFstMinimize(att_fst)
    att_fst = att_fst.strip()

    dfa = fte.cDFA.DFA(att_fst, max_len)
    retval = DFA(dfa, max_len)

    return retval
