#!/usr/bin/env python
# -*- coding: utf-8 -*-




import sys
import os
import signal
import glob
import argparse
import threading

import fte.encoder

import fteproxy.conf
import fteproxy.server
import fteproxy.client
import fteproxy.regex2dfa

# do_managed_*

from twisted.internet import reactor, error

import obfsproxy.network.network as network
import obfsproxy.common.transport_config as transport_config
import obfsproxy.transports.transports as transports
import obfsproxy.common.log as logging

from pyptlib.client import ClientTransportPlugin
from pyptlib.server import ServerTransportPlugin
from pyptlib.config import EnvError

import pprint

# unit tests

import unittest

import fteproxy.tests.test_record_layer
import fteproxy.tests.test_relay

FTE_PT_NAME = 'fte'

VERSION_FILE = os.path.join(
    fteproxy.conf.getValue('general.base_dir'), 'fteproxy', 'VERSION')
with open(VERSION_FILE) as fh:
    FTEPROXY_VERSION = fh.read().strip()


class FTEMain(threading.Thread):

    def __init__(self, args):
        threading.Thread.__init__(self)
        self._args = args

    def run(self):
        try:
            self._client = None
            self._server = None
    
            if self._args.version:
                print FTEPROXY_VERSION
                sys.exit(0)
    
            if self._args.quiet:
                fteproxy.conf.setValue('runtime.loglevel', 0)
            if self._args.managed:
                fteproxy.conf.setValue('runtime.loglevel', 0)
            if not self._args.quiet and not self._args.managed:
                print """fteproxy Copyright (C) 2012-2014 Kevin P. Dyer <kpdyer@gmail.com>
    This program comes with ABSOLUTELY NO WARRANTY.
    This is free software, and you are welcome to redistribute it under certain conditions.
    """
    
            if self._args.mode == 'test':
                test()
            if self._args.stop:
                if not self._args.mode:
                    print '--mode keyword is required with --stop'
                    sys.exit(1)
                if self._args.mode in ['client', 'server']:
                    pid_files_path = \
                        os.path.join(fteproxy.conf.getValue('general.pid_dir'),
                                     '.' + self._args.mode + '-*.pid')
                    pid_files = glob.glob(pid_files_path)
                    for pid_file in pid_files:
                        with open(pid_file) as f:
                            pid = int(f.read())
                            try:
                                os.kill(pid, signal.SIGINT)
                            except OSError:
                                fteproxy.warn('failed to remove PID file: '+pid_file)
                            os.unlink(pid_file)
                    sys.exit(0)
            if self._args.mode == 'client':
                fteproxy.conf.setValue('runtime.mode', 'client')
            elif self._args.mode == 'server':
                fteproxy.conf.setValue('runtime.mode', 'server')
            else:
                fteproxy.conf.setValue('runtime.mode', 'client')
            if self._args.client_ip:
                fteproxy.conf.setValue('runtime.client.ip', self._args.client_ip)
            if self._args.client_port:
                fteproxy.conf.setValue('runtime.client.port',
                                  int(self._args.client_port))
            if self._args.server_ip:
                fteproxy.conf.setValue('runtime.server.ip', self._args.server_ip)
            if self._args.server_port:
                fteproxy.conf.setValue('runtime.server.port',
                                  int(self._args.server_port))
            if self._args.proxy_ip:
                fteproxy.conf.setValue('runtime.proxy.ip', self._args.proxy_ip)
            if self._args.proxy_port:
                fteproxy.conf.setValue('runtime.proxy.port',
                                  int(self._args.proxy_port))
            if self._args.downstream_format:
                fteproxy.conf.setValue('runtime.state.downstream_language',
                                  self._args.downstream_format)
            if self._args.upstream_format:
                fteproxy.conf.setValue('runtime.state.upstream_language',
                                  self._args.upstream_format)
            if self._args.release:
                fteproxy.conf.setValue('fteproxy.defs.release', self._args.release)
            if self._args.key:
                if len(self._args.key) != 64:
                    fteproxy.warn('Invalid key length: ' + str(len(self._args.key)) + ', should be 64')
                    sys.exit(1)
                try:
                    binary_key = self._args.key.decode('hex')
                except:
                    fteproxy.warn('Invalid key format, must contain only 0-9a-fA-F')
                    sys.exit(1)
                fteproxy.conf.setValue('runtime.fteproxy.encrypter.key', binary_key)
    
            try:
                pid_file = os.path.join(fteproxy.conf.getValue('general.pid_dir'),
                                        '.' + fteproxy.conf.getValue('runtime.mode')
                                        + '-' + str(os.getpid()) + '.pid')
    
                with open(pid_file, 'w') as f:
                    f.write(str(os.getpid()))
            except IOError:
                fteproxy.warn('Failed to write PID file to disk: '+pid_file)
    
            if fteproxy.conf.getValue('runtime.mode') == 'client':
                try:
                    incoming_regex = fteproxy.defs.getRegex(self._args.downstream_format)
                except fteproxy.defs.InvalidRegexName:
                    fteproxy.fatal_error('Invalid format name '+self._args.downstream_format)
                    
                incoming_fixed_slice = fteproxy.defs.getFixedSlice(
                    self._args.downstream_format)
                fte.encoder.DfaEncoder(fteproxy.regex2dfa.regex2dfa(incoming_regex), incoming_fixed_slice)
                try:
                    outgoing_regex = fteproxy.defs.getRegex(self._args.upstream_format)
                except InvalidRegexName:
                    fteproxy.fatal_error('Invalid format name '+self._args.upstream_format)

                outgoing_fixed_slice = fteproxy.defs.getFixedSlice(
                    self._args.upstream_format)
                fte.encoder.DfaEncoder(fteproxy.regex2dfa.regex2dfa(outgoing_regex), outgoing_fixed_slice)
    
                if self._args.managed:
                    do_managed_client()
                else:
    
                    if not self._args.quiet:
                        print 'Client ready!'
    
                    local_ip = fteproxy.conf.getValue('runtime.client.ip')
                    local_port = fteproxy.conf.getValue('runtime.client.port')
                    remote_ip = fteproxy.conf.getValue('runtime.server.ip')
                    remote_port = fteproxy.conf.getValue('runtime.server.port')
                    self._client = fteproxy.client.listener(local_ip, local_port,
                                                       remote_ip, remote_port)
                    self._client.daemon = True
                    self._client.start()
                    self._client.join()
            elif fteproxy.conf.getValue('runtime.mode') == 'server':
    
                languages = fteproxy.defs.load_definitions()
                for language in languages.keys():
                    regex = fteproxy.defs.getRegex(language)
                    fixed_slice = fteproxy.defs.getFixedSlice(language)
                    fte.encoder.DfaEncoder(fteproxy.regex2dfa.regex2dfa(regex), fixed_slice)
    
                if self._args.managed:
                    do_managed_server()
                else:
                    local_ip = fteproxy.conf.getValue('runtime.server.ip')
                    local_port = fteproxy.conf.getValue('runtime.server.port')
                    remote_ip = fteproxy.conf.getValue('runtime.proxy.ip')
                    remote_port = fteproxy.conf.getValue('runtime.proxy.port')
                    self._server = fteproxy.server.listener(local_ip, local_port,
                                                       remote_ip, remote_port)
                    self._server.daemon = True
                    self._server.start()
                    if not self._args.quiet:
                        print 'Server ready!'
                    self._server.join()
                    
        except Exception as e:
            import traceback
            traceback.print_exc(e)
            fteproxy.fatal_error("FTEMain terminated unexpectedly: "+str(e))

    def stop(self):
        if self._client is not None:
            self._client.stop()
        if self._server is not None:
            self._server.stop()


def do_managed_client():

    log = logging.get_obfslogger()

    """Start the managed-proxy protocol as a client."""

    should_start_event_loop = False

    ptclient = ClientTransportPlugin()
    try:
        ptclient.init([FTE_PT_NAME])
    except EnvError, err:
        log.warning("Client managed-proxy protocol failed (%s)." % err)
        return

    log.debug("pyptlib gave us the following data:\n'%s'",
              pprint.pformat(ptclient.getDebugData()))

    # Apply the proxy settings if any
    proxy = ptclient.config.getProxy()
    if proxy:
        # Ensure that we have all the neccecary dependencies
        try:
            network.ensure_outgoing_proxy_dependencies()
        except network.OutgoingProxyDepFailure, err:
            ptclient.reportProxyError(str(err))
            return

        ptclient.reportProxySuccess()

    for transport in ptclient.getTransports():
        # Will hold configuration parameters for the pluggable transport
        # module.
        pt_config = transport_config.TransportConfig()
        pt_config.setStateLocation(ptclient.config.getStateLocation())
        pt_config.fte_client_socks_version = -1
        pt_config.setProxy(proxy)

        try:
            addrport = fteproxy.launch_transport_listener(
                transport, None, 'socks', None, pt_config)
        except transports.TransportNotFound:
            log.warning("Could not find transport '%s'" % transport)
            ptclient.reportMethodError(transport, "Could not find transport.")
            continue
        except error.CannotListenError:
            log.warning("Could not set up listener for '%s'." % transport)
            ptclient.reportMethodError(transport, "Could not set up listener.")
            continue

        should_start_event_loop = True
        log.debug("Successfully launched '%s' at '%s'" %
                  (transport, log.safe_addr_str(str(addrport))))
        if pt_config.fte_client_socks_version == 5:
            ptclient.reportMethodSuccess(transport, "socks5", addrport, None, None)
        elif pt_config.fte_client_socks_version == 4:
            ptclient.reportMethodSuccess(transport, "socks4", addrport, None, None)
        else:
            # This should *never* happen unless launch_transport_listener()
            # decides to report a SOCKS version from the future.
            log.warning("Listener SOCKS version unknown." )
            ptclient.reportMethodError(transport,
                                       "Listener SOCKS version unknown.")
            should_start_event_loop = False

    ptclient.reportMethodsEnd()

    if should_start_event_loop:
        log.info("Starting up the event loop.")
        reactor.run()
    else:
        log.info("No transports launched. Nothing to do.")


def do_managed_server():

    log = logging.get_obfslogger()

    """Start the managed-proxy protocol as a server."""

    should_start_event_loop = False

    ptserver = ServerTransportPlugin()
    try:
        ptserver.init([FTE_PT_NAME])
    except EnvError, err:
        log.warning("Server managed-proxy protocol failed (%s)." % err)
        return

    log.debug("pyptlib gave us the following data:\n'%s'",
              pprint.pformat(ptserver.getDebugData()))

    ext_orport = ptserver.config.getExtendedORPort()
    authcookie = ptserver.config.getAuthCookieFile()
    orport = ptserver.config.getORPort()
    server_transport_options = ptserver.config.getServerTransportOptions()
    for transport, transport_bindaddr in ptserver.getBindAddresses().items():

        # Will hold configuration parameters for the pluggable transport
        # module.
        pt_config = transport_config.TransportConfig()
        pt_config.setStateLocation(ptserver.config.getStateLocation())
        transport_options = ""
        if server_transport_options and transport in server_transport_options:
            transport_options = server_transport_options[transport]
            pt_config.setServerTransportOptions(transport_options)

        try:
            if ext_orport:
                addrport = fteproxy.launch_transport_listener(transport,
                                                         transport_bindaddr,
                                                         'ext_server',
                                                         ext_orport,
                                                         pt_config,
                                                         ext_or_cookie_file=authcookie)
            else:
                addrport = fteproxy.launch_transport_listener(transport,
                                                         transport_bindaddr,
                                                         'server',
                                                         orport,
                                                         pt_config)
        except transports.TransportNotFound:
            log.warning("Could not find transport '%s'" % transport)
            ptserver.reportMethodError(transport, "Could not find transport.")
            continue
        except error.CannotListenError:
            log.warning("Could not set up listener for '%s'." % transport)
            ptserver.reportMethodError(transport, "Could not set up listener.")
            continue

        should_start_event_loop = True

        # Include server transport options in the log message if we got 'em
        extra_log = ""
        if transport_options:
            extra_log = " (server transport options: '%s')" % str(
                transport_options)
        log.debug("Successfully launched '%s' at '%s'%s" %
                  (transport, log.safe_addr_str(str(addrport)), extra_log))

        # Report success for this transport.
        # (We leave the 'options' as None and let pyptlib handle the
        # SMETHOD argument sending.)
        ptserver.reportMethodSuccess(transport, addrport, None)

    ptserver.reportMethodsEnd()

    if should_start_event_loop:
        log.info("Starting up the event loop.")
        reactor.run()
    else:
        log.info("No transports launched. Nothing to do.")


def test():
    try:    
        suite_record_layer = unittest.TestLoader().loadTestsFromTestCase(
            fteproxy.tests.test_record_layer.Tests)
        suite_relay = unittest.TestLoader().loadTestsFromTestCase(
            fteproxy.tests.test_relay.Tests)
        suites = [
            suite_relay,
            suite_record_layer,
        ]
        alltests = unittest.TestSuite(suites)
        unittest.TextTestRunner(verbosity=2).run(alltests)
        sys.exit(0)
    except Exception as e:
        fteproxy.warn("Unit tests failed: "+str(e))


def get_args():
    parser = argparse.ArgumentParser(prog='fteproxy',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--version', action='store_true', default=False,
                        help='Output the version of fteproxy, then quit.')
    parser.add_argument('--mode',
                        default='client',
                        metavar='(client|server|test)',
                        help='Relay mode: client or server')
    parser.add_argument('--stop', action='store_true',
                        help='Shutdown daemon process')
    parser.add_argument('--upstream-format',
                        help='Client-to-server language format',
                        default=fteproxy.conf.getValue('runtime.state.upstream_language'
                                                  ))
    parser.add_argument('--downstream-format',
                        help='Server-to-client language format',
                        default=fteproxy.conf.getValue('runtime.state.downstream_language'
                                                  ))
    parser.add_argument('--client_ip',
                        help='Client-side listening IP',
                        default=fteproxy.conf.getValue('runtime.client.ip'
                                                  ))
    parser.add_argument('--client_port',
                        help='Client-side listening port',
                        default=fteproxy.conf.getValue('runtime.client.port'
                                                  ))
    parser.add_argument('--server_ip',
                        help='Server-side listening IP',
                        default=fteproxy.conf.getValue('runtime.server.ip'
                                                  ))
    parser.add_argument('--server_port',
                        help='Server-side listening port',
                        default=fteproxy.conf.getValue('runtime.server.port'
                                                  ))
    parser.add_argument('--proxy_ip',
                        help='Forwarding-proxy (SOCKS) listening IP',
                        default=fteproxy.conf.getValue('runtime.proxy.ip'
                                                  ))
    parser.add_argument('--proxy_port',
                        help='Forwarding-proxy (SOCKS) listening port',
                        default=fteproxy.conf.getValue('runtime.proxy.port'
                                                  ))
    parser.add_argument('--quiet', action='store_true', default=False,
                        help='Be completely silent. Print nothing.')
    parser.add_argument('--release',
                        help='Definitions file to use, specified as YYYYMMDD',
                        default=fteproxy.conf.getValue('fteproxy.defs.release'))
    parser.add_argument('--managed',
                        help="Start in pluggable transport managed mode, for use with Tor.",
                        action='store_true',
                        default=False)
    parser.add_argument('--key',
                        help='Cryptographic key, hex, must be exactly 64 characters',
                        default=fteproxy.conf.getValue('runtime.fteproxy.encrypter.key'
                                                  ))
    args = parser.parse_args(sys.argv[1:])

    return args


def main():
    global running
    running = True
    def signal_handler(signal, frame):
        global running
        running = False
    signal.signal(signal.SIGINT, signal_handler)

    try:
        args = get_args()
        main = FTEMain(args)
        if args.managed:
            main.run()
        else:
            main.daemon = True
            main.start()
            while running and main.is_alive():
                main.join(timeout=0.5)
            main.stop()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        fteproxy.fatal_error("Main thread terminated unexpectedly: "+str(e))
    finally:
        if fteproxy.conf.getValue('runtime.mode'):
            pid_file = os.path.join(fteproxy.conf.getValue('general.pid_dir'
                                                      ), '.'
                                    + fteproxy.conf.getValue('runtime.mode')
                                    + '-' + str(os.getpid()) + '.pid')
            if pid_file and os.path.exists(pid_file):
                os.unlink(pid_file)
