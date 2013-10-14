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
import unittest
import string
import sys
import time
import fte.relay


def doTest(langset):
    [lang_upstream, lang_downstream] = langset
    print (lang_upstream, lang_downstream)
    fte.conf.setValue('runtime.state.upstream_language', lang_upstream)
    fte.conf.setValue('runtime.state.downstream_language',
                      lang_downstream)
    encrypter = fte.encrypter.Encrypter()
    encoder = fte.encoder.RegexEncoder(lang_upstream)
    for i in range(2 ** 7):
        covertext = fte.relay.negotiate(encrypter, encoder)
        (negotiated_upstream, negotiated_downstream, covertext) = \
            fte.relay.negotiate_acknowledge(encrypter, covertext)
        assert lang_upstream == negotiated_upstream, (lang_upstream,
                                                      negotiated_upstream)
        assert lang_downstream == negotiated_downstream, \
            (lang_downstream, negotiated_downstream)


class TestRelay(unittest.TestCase):

    def testNegotiate(self):
        langs = []
        for lang in fte.conf.getValue('languages.regex'):
            encoder = fte.encoder.RegexEncoder(lang)
        for lang_upstream in fte.conf.getValue('languages.regex'):
            if not lang_upstream.endswith('request'):
                continue
            lang_downstream = string.replace(lang_upstream, 'request',
                                             'response')
            langs.append([lang_upstream, lang_downstream])
        for lang in langs:
            doTest(lang)


if __name__ == '__main__':
    unittest.main()