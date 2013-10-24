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
import gmpy

import fte.conf
import fte.encrypter
import fte.bit_ops
import fte.dfa


class DecodeFailureException(Exception):

    pass


class InvalidInputException(Exception):

    pass


class RegexEncoder(object):
    COVERTEXT_HEADER_LEN = 4

    def __init__(self, regex_name):
        pass
        
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
