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
import math

import fte.conf
import fte.encrypter
import fte.bit_ops
import fte.dfa
import fte.defs


class DecodeFailureException(Exception):
    pass


class InvalidInputException(Exception):
    pass


_instance = {}


class RegexEncoder(object):

    def __new__(self, regex, max_len):
        global _instance
        if not _instance.get((regex,max_len)):
            _instance[(regex,max_len)] = RegexEncoderObject(regex, max_len)
        return _instance[(regex,max_len)]


class RegexEncoderObject(object):
    COVERTEXT_HEADER_LEN = 4

    def __init__(self, regex, max_len):
        self._regex = regex
        self._max_len = max_len
        self._dfa = fte.dfa.from_regex(self._regex, self._max_len)

    def getCapacity(self, ):
        return self._dfa._capacity

    def encode(self, X):
        if not isinstance(X, str):
            raise InvalidInputException('Input must be of type string.')

        maximumBytesToRank = int(math.floor(self.getCapacity() / 8.0))

        msg_len = min(
            maximumBytesToRank - RegexEncoderObject.COVERTEXT_HEADER_LEN, len(X))

        msg_len_header = fte.bit_ops.long_to_bytes(msg_len)
        msg_len_header = '\xFF' + \
            string.rjust(
                msg_len_header, RegexEncoderObject.COVERTEXT_HEADER_LEN - 1, '\x00')

        unrank_payload = msg_len_header + \
            X[:maximumBytesToRank - RegexEncoderObject.COVERTEXT_HEADER_LEN]
        unrank_payload = fte.bit_ops.bytes_to_long(unrank_payload)

        formatted_covertext_header = self._dfa.unrank(unrank_payload)
        unformatted_covertext_body = X[
            maximumBytesToRank - RegexEncoderObject.COVERTEXT_HEADER_LEN:]

        covertext = formatted_covertext_header + unformatted_covertext_body

        return covertext

    def decode(self, covertext):
        if not isinstance(covertext, str):
            raise InvalidInputException('Input must be of type string.')

        assert len(covertext) >= self._max_len, (len(covertext), self._max_len)

        rank_payload = self._dfa.rank(covertext[:self._max_len])
        X = fte.bit_ops.long_to_bytes(rank_payload)
        msg_len = fte.bit_ops.bytes_to_long(X[1:4])
        X = X[-msg_len:] + covertext[self._max_len:]

        return X
