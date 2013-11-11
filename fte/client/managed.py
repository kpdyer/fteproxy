#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file was taken from obfsproxy by the Tor Project.
# https://gitweb.torproject.org/pluggable-transports/obfsproxy.git/blob_plain/HEAD:/obfsproxy/transports/base.py

import pyptlib.util

import obfsproxy.common.log as logging

import argparse

log = logging.get_obfslogger()

"""
This module contains BaseTransport, a pluggable transport skeleton class.
"""

def addrport(string):
    """
    Receive '<addr>:<port>' and return (<addr>,<port>).
    Used during argparse CLI parsing.
    """
    try:
        return pyptlib.util.parse_addr_spec(string)
    except ValueError, err:
        raise argparse.ArgumentTypeError(err)

class BaseTransport(object):
    """
    The BaseTransport class is a skeleton class for pluggable transports.
    It contains callbacks that your pluggable transports should
    override and customize.
    """

    def __init__(self):
        pass

    def handshake(self, circuit):
        """
        The Circuit 'circuit' was completed, and this is a good time
        to do your transport-specific handshake on its downstream side.
        """
        pass

    def circuitDestroyed(self, circuit, reason, side):
        """
        Circuit 'circuit' was tore down.
        Both connections of the circuit are closed when this callback triggers.
        """
        pass

    def receivedDownstream(self, data, circuit):
        """
        Received 'data' in the downstream side of 'circuit'.
        'data' is an obfsproxy.network.buffer.Buffer.
        """
        pass

    def receivedUpstream(self, data, circuit):
        """
        Received 'data' in the upstream side of 'circuit'.
        'data' is an obfsproxy.network.buffer.Buffer.
        """
        pass

    def handle_socks_args(self, args):
        """
        'args' is a list of k=v strings that serve as configuration
        parameters to the pluggable transport.
        """
        pass

    @classmethod
    def register_external_mode_cli(cls, subparser):
        """
        Given an argparse ArgumentParser in 'subparser', register
        some default external-mode CLI arguments.

        Transports with more complex CLI are expected to override this
        function.
        """

        subparser.add_argument('mode', choices=['server', 'ext_server', 'client', 'socks'])
        subparser.add_argument('listen_addr', type=addrport)
        subparser.add_argument('--dest', type=addrport, help='Destination address')
        subparser.add_argument('--ext-cookie-file', type=str,
                               help='Filesystem path where the Extended ORPort authentication cookie is stored.')

    @classmethod
    def validate_external_mode_cli(cls, args):
        """
        Given the parsed CLI arguments in 'args', validate them and
        make sure they make sense. Return True if they are kosher,
        otherwise return False.

        Override for your own needs.
        """

        # If we are not 'socks', we need to have a static destination
        # to send our data to.
        if (args.mode != 'socks') and (not args.dest):
            log.error("'client' and 'server' modes need a destination address.")
            return False

        if (args.mode != 'ext_server') and args.ext_cookie_file:
            log.error("No need for --ext-cookie-file if not an ext_server.")
            return False

        if (args.mode == 'ext_server') and (not args.ext_cookie_file):
            log.error("You need to specify --ext-cookie-file as an ext_server.")
            return False

        return True


class DummyTransport(BaseTransport):
    """
    Implements the dummy protocol. A protocol that simply proxies data
    without obfuscating them.
    """

    def __init__(self, transport_config):
        pass

    def receivedDownstream(self, data, circuit):
        """
        Got data from downstream; relay them upstream.
        """

        circuit.upstream.write(data.read())

    def receivedUpstream(self, data, circuit):
        """
        Got data from upstream; relay them downstream.
        """

        circuit.downstream.write(data.read())
        
class PluggableTransportError(Exception): pass
class SOCKSArgsError(Exception): pass