#!/usr/bin/env python
# -*- coding: utf-8 -*-




import fteproxy.relay


class listener(fteproxy.relay.listener):

    def onNewIncomingConnection(self, socket):
        """On an incoming data stream we wrap it with ``fteproxy.wrap_socket``, with no parameters.
        By default we want the regular expressions to be negotiated in-band, specified by the client.
        """

        socket = fteproxy.wrap_socket(socket)

        return socket
