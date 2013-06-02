#!/usr/bin/env python
import os
import sys
import glob
import doctest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

os.chdir(os.path.dirname(__file__) or '.')

def testall():
    for file in glob.glob(os.path.join(os.path.dirname(__file__), "*.txt")):
        print "Testing %s..." % file
        doctest.testfile(os.path.join(".", os.path.basename(file)))

if __name__ == "__main__":
    testall()
