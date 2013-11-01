#!/usr/bin/python
# -*- coding: utf-8 -*-

"""This is a server-side example of the pyptlib API."""

import sys

from pyptlib.server import ServerTransportPlugin
from pyptlib.config import EnvError

if __name__ == '__main__':
    server = ServerTransportPlugin()
    try:
        server.init(["blackfish", "bluefish"])
    except EnvError, err:
        print "pyptlib could not bootstrap ('%s')." % str(err)
        sys.exit(1)

    for transport, transport_bindaddr in server.getBindAddresses().items():
        # Try to spawn transports and make them listen in the ports
        # that Tor wants. Report failure or success appropriately.

        # 'transport' is a string with the name of the transport.
        # 'transport_bindaddr' is the (<ip>,<port>) where that
        # transport should listen for connections.

        try:
            bind_addrport = your_function_that_launches_transports(transport, transport_bindaddr)
        except YourFailException, err:
            reportFailure(transport, "Failed to launch ('%s')." % str(err))
            continue

        server.reportMethodSuccess(transport, bind_addrport, None)

    # Report back after we finish spawning transports.
    server.reportMethodsEnd()
