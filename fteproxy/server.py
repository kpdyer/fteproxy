#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import fteproxy
import fteproxy.client
import fteproxy.conf
import fteproxy.relay


class listener(fteproxy.relay.listener):

    def onNewIncomingConnection(self, socket):
        """Wrap an incoming connection in the server role.

        The server passes no format and no mode: it learns both from the
        client's first record, and answers a record it cannot validate with
        silence.
        """
        # TODO(PR4): the flat command line has no state directory to keep a
        # server key in, so the keypair is derived from the shared secret.
        server_key, _ = fteproxy.client.shim_keypair_from_shared_key(
            fteproxy.conf.getValue('runtime.fteproxy.encrypter.key'))
        return fteproxy.wrap_socket(socket, server_key=server_key)
