#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import fteproxy
import fteproxy.conf
import fteproxy.defs
import fteproxy.relay


class listener(fteproxy.relay.listener):

    def onNewOutgoingConnection(self, socket):
        """Wrap the connection to the fteproxy server in the client role.

        The base format and the record-layer mode are the client's choices and
        travel in the handshake; the server follows them.
        """
        base = fteproxy.defs.base_name(
            fteproxy.conf.getValue('runtime.state.upstream_language'))
        mode = fteproxy.conf.getValue('runtime.fteproxy.record_layer.mode')
        # TODO(PR4): the flat command line still carries a shared secret rather
        # than a connection string, so the client derives the server's identity
        # from it. PR4 replaces this with the server-id parsed from the URI.
        _, server_public = shim_keypair_from_shared_key(
            fteproxy.conf.getValue('runtime.fteproxy.encrypter.key'))
        return fteproxy.wrap_socket(socket, server_id=server_public,
                                    format=base, mode=mode)


# TODO(PR4): delete with the flat command line.
def shim_keypair_from_shared_key(key):
    """Derive a fixed server keypair from the pre-0.4 shared secret.

    The 0.4 protocol authenticates the server with a keypair, and the 0.4
    command line hands the client that keypair's public half in a connection
    string. Until PR4 lands the new command line, ``--key``/``--key-file``
    still name a secret both endpoints hold, so both derive the same keypair
    from it and the real handshake runs unchanged. Nothing about the protocol
    is weakened by this; what it lacks is the operational property that the
    client only ever needs a public key.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    private = HKDF(algorithm=hashes.SHA256(), length=32, salt=b'',
                   info=b'fteproxy/shim/shared-key-server-identity').derive(key)
    return private, fteproxy.server_id(private)
