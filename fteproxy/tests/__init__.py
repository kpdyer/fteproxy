#!/usr/bin/env python3
# -*- coding: utf-8 -*-



import unittest
from . import test_record_layer
from . import test_relay
from . import test_python3


def suite():
    suite = unittest.TestSuite()
    suite.addTests(test_record_layer.suite())
    suite.addTests(test_relay.suite())
    suite.addTests(test_python3.suite())
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())
