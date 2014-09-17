#!/usr/bin/env python
# -*- coding: utf-8 -*-



import unittest
import test_record_layer
import test_relay


def suite():
    suite = unittest.TestSuite()
    suite.addTests(test_record_layer.suite())
    suite.addTests(test_relay.suite())
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())
