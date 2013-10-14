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


import unittest
import sys
sys.path.append('.')
sys.path.append('fte')
import fte.conf
if fte.conf.getValue('modules.regex.enable'):
    import fte.tests.regex
import fte.tests.encrypter
import fte.tests.record_layer
import fte.tests.bit_ops
import fte.tests.relay
if fte.conf.getValue('modules.regex.enable'):
    suite_regex = \
        unittest.TestLoader().loadTestsFromTestCase(
            fte.tests.regex.TestEncoders)
suite_encrypter = \
    unittest.TestLoader().loadTestsFromTestCase(
        fte.tests.encrypter.TestEncoders)
suite_record_layer = \
    unittest.TestLoader().loadTestsFromTestCase(
        fte.tests.record_layer.TestEncoders)
suite_relay = \
    unittest.TestLoader().loadTestsFromTestCase(fte.tests.relay.TestRelay)
suite_bit_ops = \
    unittest.TestLoader().loadTestsFromTestCase(fte.tests.bit_ops.TestEncoders)
suites = [
    suite_bit_ops,
    suite_regex,
    suite_encrypter,
    suite_relay,
    suite_record_layer,
]
alltests = unittest.TestSuite(suites)
unittest.TextTestRunner(verbosity=2, failfast=True).run(alltests)
