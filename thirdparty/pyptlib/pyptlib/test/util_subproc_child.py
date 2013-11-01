#!/usr/bin/python

import signal
import sys
import time

def hangForever(signum=0, sframe=None):
    time.sleep(1000)

def child_default(subcmd, *argv):
    time.sleep(100)

def child_default_io(subcmd, *argv):
    print "child printing output"

def child_killall_kill(subcmd, *argv):
    signal.signal(signal.SIGINT, hangForever)
    signal.signal(signal.SIGTERM, hangForever)
    child_default(None)

if __name__ == '__main__':
    getattr(sys.modules[__name__], "child_%s" % sys.argv[1])(*sys.argv[1:])
