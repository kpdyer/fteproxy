#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Public client-side pyptlib API.
"""

from pyptlib.core import TransportPlugin
from pyptlib.client_config import ClientConfig


class ClientTransportPlugin(TransportPlugin):
    """
    Runtime process for a client TransportPlugin.
    """
    configType = ClientConfig
    methodName = 'CMETHOD'

    def reportMethodSuccess(self, name, protocol, addrport, args=None, optArgs=None):
        """
        Write a message to stdout announcing that a transport was
        successfully launched.

        :param str name: Name of transport.
        :param str protocol: Name of protocol to communicate using.
        :param tuple addrport: (addr,port) where this transport is listening for connections.
        :param str args: ARGS field for this transport.
        :param str optArgs: OPT-ARGS field for this transport.
        """

        methodLine = 'CMETHOD %s %s %s:%s' % (name, protocol,
                addrport[0], addrport[1])
        if args and len(args) > 0:
            methodLine = methodLine + ' ARGS=' + args.join(',')
        if optArgs and len(optArgs) > 0:
            methodLine = methodLine + ' OPT-ARGS=' + args.join(',')
        self.emit(methodLine)


def init(supported_transports):
    """DEPRECATED. Use ClientTransportPlugin().init() instead."""
    client = ClientTransportPlugin()

    client.init(supported_transports)
    retval = {}
    retval['state_loc'] = client.config.getStateLocation()
    retval['transports'] = client.getTransports()

    return retval

def reportSuccess(name, socksVersion, addrport, args=None, optArgs=None):
    """DEPRECATED. Use ClientTransportPlugin().reportMethodSuccess() instead."""
    config = ClientTransportPlugin()
    config.reportMethodSuccess(name, "socks%s" % socksVersion, addrport, args, optArgs)

def reportFailure(name, message):
    """DEPRECATED. Use ClientTransportPlugin().reportMethodError() instead."""
    config = ClientTransportPlugin()
    config.reportMethodError(name, message)

def reportEnd():
    """DEPRECATED. Use ClientTransportPlugin().reportMethodsEnd() instead."""
    config = ClientTransportPlugin()
    config.reportMethodsEnd()
