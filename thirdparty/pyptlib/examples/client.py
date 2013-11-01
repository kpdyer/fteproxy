#!/usr/bin/python
# -*- coding: utf-8 -*-

"""This is a client-side example of the pyptlib API."""

import sys

from pyptlib.client import ClientTransportPlugin
from pyptlib.config import EnvError

if __name__ == '__main__':
    client = ClientTransportPlugin()
    try:
        client.init(["blackfish", "bluefish"])
    except EnvError, err:
        print "pyptlib could not bootstrap ('%s')." % str(err)
        sys.exit(1)

    for transport in client.getTransports():
        # Spawn all the transports in the list, and for each spawned
        # transport report back the port where it is listening, and
        # the SOCKS version it supports.

        try:
            socks_version, bind_addrport = your_function_that_launches_transports(transport)
        except YourFailException, err:
            reportFailure(transport, "Failed to launch ('%s')." % str(err))
            continue

        client.reportMethodSuccess(transport, socks_version, bind_addrport, None, None)

    # After spawning our transports, report that we are done.
    client.reportMethodsEnd()
