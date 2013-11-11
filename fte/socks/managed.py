#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file was taken from obfsproxy, by the Tor Project.
# https://gitweb.torproject.org/pluggable-transports/obfsproxy.git/blob_plain/HEAD:/obfsproxy/network/socks.py

import csv

from twisted.protocols import socks
from twisted.internet.protocol import Factory

import obfsproxy.common.log as logging
import obfsproxy.network.network as network
import obfsproxy.transports.base as base

log = logging.get_obfslogger()


def split_socks_args(args_str):
    """
    Given a string containing the SOCKS arguments (delimited by
    semicolons, and with semicolons and backslashes escaped), parse it
    and return a list of the unescaped SOCKS arguments.
    """
    return csv.reader([args_str], delimiter=';', escapechar='\\').next()

class MySOCKSv4Outgoing(socks.SOCKSv4Outgoing, network.GenericProtocol):
    """
    Represents a downstream connection from the SOCKS server to the
    destination.

    It monkey-patches socks.SOCKSv4Outgoing, because we need to pass
    our data to the pluggable transport before proxying them
    (Twisted's socks module did not support that).

    Attributes:
    circuit: The circuit this connection belongs to.
    buffer: Buffer that holds data that can't be proxied right
            away. This can happen because the circuit is not yet
            complete, or because the pluggable transport needs more
            data before deciding what to do.
    """

    def __init__(self, socksProtocol):
        """
        Constructor.

        'socksProtocol' is a 'SOCKSv4Protocol' object.
        """
        self.name = "socks_down_%s" % hex(id(self))
        self.socksProtocol = socksProtocol

        network.GenericProtocol.__init__(self, socksProtocol.circuit)
        return super(MySOCKSv4Outgoing, self).__init__(socksProtocol)

    def dataReceived(self, data):
        log.debug("%s: Received %d bytes." % (self.name, len(data)))

        # If the circuit was not set up, set it up now.
        if not self.circuit.circuitIsReady():
            self.socksProtocol.set_up_circuit()

        self.buffer.write(data)
        self.circuit.dataReceived(self.buffer, self)

    def close(self): # XXX code duplication
        """
        Close the connection.
        """
        if self.closed:
            return # NOP if already closed

        log.debug("%s: Closing connection." % self.name)

        self.transport.loseConnection()
        self.closed = True

    def connectionLost(self, reason):
        network.GenericProtocol.connectionLost(self, reason)

# Monkey patches socks.SOCKSv4Outgoing with our own class.
socks.SOCKSv4Outgoing = MySOCKSv4Outgoing

class SOCKSv4Protocol(socks.SOCKSv4, network.GenericProtocol):
    """
    Represents an upstream connection from a SOCKS client to our SOCKS
    server.

    It overrides socks.SOCKSv4 because py-obfsproxy's connections need
    to have a circuit and obfuscate traffic before proxying it.
    """

    def __init__(self, circuit):
        self.name = "socks_up_%s" % hex(id(self))

        network.GenericProtocol.__init__(self, circuit)
        socks.SOCKSv4.__init__(self)

    def dataReceived(self, data):
        """
        Received some 'data'. They might be SOCKS handshake data, or
        actual upstream traffic. Figure out what it is and either
        complete the SOCKS handshake or proxy the traffic.
        """

        # SOCKS handshake not completed yet: let the overriden socks
        # module complete the handshake.
        if not self.otherConn:
            log.debug("%s: Received SOCKS handshake data." % self.name)
            return socks.SOCKSv4.dataReceived(self, data)

        log.debug("%s: Received %d bytes." % (self.name, len(data)))
        self.buffer.write(data)

        """
        If we came here with an incomplete circuit, it means that we
        finished the SOCKS handshake and connected downstream. Set up
        our circuit and start proxying traffic.
        """
        if not self.circuit.circuitIsReady():
            self.set_up_circuit()

        self.circuit.dataReceived(self.buffer, self)

    def set_up_circuit(self):
        """
        Set the upstream/downstream SOCKS connections on the circuit.
        """

        assert(self.otherConn)
        self.circuit.setDownstreamConnection(self.otherConn)
        self.circuit.setUpstreamConnection(self)

    def authorize(self, code, server, port, user):
        """
        (Overriden)
        Accept or reject a SOCKS client that wants to connect to
        'server':'port', with the SOCKS4 username 'user'.
        """

        if not user: # No SOCKS arguments were specified.
            return True

        # If the client sent us SOCKS arguments, we must parse them
        # and send them to the appropriate transport.
        log.debug("Got '%s' as SOCKS arguments." % user)

        try:
            socks_args = split_socks_args(user)
        except csv.Error, err:
            log.warning("split_socks_args failed (%s)" % str(err))
            return False

        try:
            self.circuit.transport.handle_socks_args(socks_args)
        except base.SOCKSArgsError:
            return False # Transports should log the issue themselves

        return True

    def connectionLost(self, reason):
        network.GenericProtocol.connectionLost(self, reason)

class SOCKSv4Factory(Factory):
    """
    A SOCKSv4 factory.
    """

    def __init__(self, transport_class, pt_config):
        self.transport_class = transport_class
        self.pt_config  = pt_config

        self.name = "socks_fact_%s" % hex(id(self))

    def startFactory(self):
        log.debug("%s: Starting up SOCKS server factory." % self.name)

    def buildProtocol(self, addr):
        log.debug("%s: New connection." % self.name)

        circuit = network.Circuit(self.transport_class(self.pt_config))

        return SOCKSv4Protocol(circuit)
