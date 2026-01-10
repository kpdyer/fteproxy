#!/usr/bin/env python3
# -*- coding: utf-8 -*-




import sys
import os
import signal
import glob
import argparse
import threading
import traceback

import fte.encoder

import fteproxy.conf
import fteproxy.server
import fteproxy.client

# unit tests

import unittest

import fteproxy.tests.test_record_layer
import fteproxy.tests.test_relay

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

            if not self._args.quiet:
                print("""fteproxy Copyright (C) 2012-2026 Kevin P. Dyer <kpdyer@gmail.com>
    This program comes with ABSOLUTELY NO WARRANTY.
    This is free software, and you are welcome to redistribute it under certain conditions.
    """)

            if self._args.mode == 'test':
                test()
            if self._args.stop:
                FTEMain.do_stop(self)

            try:
                pid_file = get_pid_file()

                with open(pid_file, 'w') as f:
                    f.write(str(os.getpid()))
            except IOError:
                fteproxy.warn('Failed to write PID file to disk: '+pid_file)

            if fteproxy.conf.getValue('runtime.mode') == 'client':
                FTEMain.do_client(self)
            elif fteproxy.conf.getValue('runtime.mode') == 'server':
                FTEMain.do_server(self)

        except Exception as e:
            traceback.print_exc()
            fteproxy.fatal_error("FTEMain terminated unexpectedly: "+str(e))

    def stop(self):
        if self._client is not None:
            self._client.stop()
        if self._server is not None:
            self._server.stop()

    def do_stop(self):
        if self._args.mode != 'test':
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

    def init_listener(self, mode):
        server_ip = fteproxy.conf.getValue('runtime.server.ip')
        server_port = fteproxy.conf.getValue('runtime.server.port')
        if mode == 'client':
            client_ip = fteproxy.conf.getValue('runtime.client.ip')
            client_port = fteproxy.conf.getValue('runtime.client.port')
            return fteproxy.client.listener(client_ip, client_port,
                                            server_ip, server_port)
        elif mode == 'server':
            proxy_ip = fteproxy.conf.getValue('runtime.proxy.ip')
            proxy_port = fteproxy.conf.getValue('runtime.proxy.port')
            return fteproxy.server.listener(server_ip, server_port,
                                            proxy_ip, proxy_port)
        else:
            fteproxy.fatal_error('Unexpected mode in init_listener: ' + mode)

    def init_DfaEncoder(self, stream_format):

        K1 = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')[:16]
        K2 = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')[16:]

        try:
            regex = fteproxy.defs.getRegex(stream_format)
        except fteproxy.defs.InvalidRegexName:
            fteproxy.fatal_error('Invalid format name ' + stream_format)

        fixed_slice = fteproxy.defs.getFixedSlice(stream_format)
        fte.encoder.DfaEncoder(regex, fixed_slice, K1, K2)

    def do_client(self):

        FTEMain.init_DfaEncoder(self, self._args.downstream_format)
        FTEMain.init_DfaEncoder(self, self._args.upstream_format)

        if not self._args.quiet:
            print('Client ready!')

        self._client = FTEMain.init_listener(self, 'client')
        self._client.daemon = True
        self._client.start()
        self._client.join()

    def do_server(self):

        languages = fteproxy.defs.load_definitions()
        for language in languages.keys():
            FTEMain.init_DfaEncoder(self, language)

        self._server = FTEMain.init_listener(self, 'server')
        self._server.daemon = True
        self._server.start()
        if not self._args.quiet:
            print('Server ready!')
        self._server.join()


def get_pid_file():
    pid_file = os.path.join(fteproxy.conf.getValue('general.pid_dir'),
                              '.' + fteproxy.conf.getValue('runtime.mode')
                            + '-' + str(os.getpid()) + '.pid')
    return pid_file


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

    class setConfValue(argparse.Action):
        def __call__(self, parser, namespace, values, options_string):
            args_to_conf = {
                "--quiet":              "runtime.loglevel",
                "--mode":               "runtime.mode",
                "--client_ip":          "runtime.client.ip",
                "--client_port":        "runtime.client.port",
                "--server_ip":          "runtime.server.ip",
                "--server_port":        "runtime.server.port",
                "--proxy_ip":           "runtime.proxy.ip",
                "--proxy_port":         "runtime.proxy.port",
                "--downstream-format":  "runtime.state.downstream_language",
                "--upstream-format":    "runtime.state.upstream_language",
                "--release":            "fteproxy.defs.release",
                "--key":                "runtime.fteproxy.encrypter.key",
            }

            if self.dest == "key":
                if len(values) != 64:
                    fteproxy.warn('Invalid key length: ' + str(len(values))
                                  + ', should be 64')
                    sys.exit(1)
                try:
                    values = bytes.fromhex(values)
                except ValueError:
                    fteproxy.warn('Invalid key format, must contain only 0-9a-fA-F')
                    sys.exit(1)

            if self.dest == 'quiet':
                fteproxy.conf.setValue(args_to_conf[options_string], 0)
                setattr(namespace, self.dest, True)
            else:
                setattr(namespace, self.dest, values)
                if "port" in self.dest:
                    values = int(values)
                fteproxy.conf.setValue(args_to_conf[options_string], values)

    parser = argparse.ArgumentParser(prog='fteproxy',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--version', action='version', version=FTEPROXY_VERSION,
                        help='Output the version of fteproxy, then quit.')
    parser.add_argument('--mode', action=setConfValue, default='client',
                        metavar='(client|server|test)',
                        choices=['client', 'server', 'test'],
                        help='Relay mode: client or server')
    parser.add_argument('--stop', action='store_true',
                        help='Shutdown daemon process')
    parser.add_argument('--upstream-format', action=setConfValue,
                        help='Client-to-server language format',
                        default=fteproxy.conf.getValue('runtime.state.upstream_language'
                                                  ))
    parser.add_argument('--downstream-format', action=setConfValue,
                        help='Server-to-client language format',
                        default=fteproxy.conf.getValue('runtime.state.downstream_language'
                                                  ))
    parser.add_argument('--client_ip', action=setConfValue,
                        help='Client-side listening IP',
                        default=fteproxy.conf.getValue('runtime.client.ip'
                                                  ))
    parser.add_argument('--client_port', action=setConfValue,
                        help='Client-side listening port',
                        default=fteproxy.conf.getValue('runtime.client.port'
                                                  ))
    parser.add_argument('--server_ip', action=setConfValue,
                        help='Server-side listening IP',
                        default=fteproxy.conf.getValue('runtime.server.ip'
                                                  ))
    parser.add_argument('--server_port', action=setConfValue,
                        help='Server-side listening port',
                        default=fteproxy.conf.getValue('runtime.server.port'
                                                  ))
    parser.add_argument('--proxy_ip', action=setConfValue,
                        help='Forwarding-proxy listening IP',
                        default=fteproxy.conf.getValue('runtime.proxy.ip'
                                                  ))
    parser.add_argument('--proxy_port', action=setConfValue,
                        help='Forwarding-proxy listening port',
                        default=fteproxy.conf.getValue('runtime.proxy.port'
                                                  ))
    parser.add_argument('--quiet', action=setConfValue, default=False,
                        help='Be completely silent. Print nothing.', nargs=0)
    parser.add_argument('--release', action=setConfValue,
                        help='Definitions file to use, specified as YYYYMMDD',
                        default=fteproxy.conf.getValue('fteproxy.defs.release'))
    parser.add_argument('--key', action=setConfValue,
                        help='Cryptographic key, hex, must be exactly 64 characters',
                        default=fteproxy.conf.getValue('runtime.fteproxy.encrypter.key'
                                                  ).hex())
    args = parser.parse_args(sys.argv[1:])

    if args.stop and not args.mode:
        parser.error('--mode keyword is required with --stop')

    if not args.mode:  # set client mode in conf if not set
        fteproxy.conf.setValue('runtime.mode', 'client')

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
        main_thread = FTEMain(args)
        main_thread.daemon = True
        main_thread.start()
        while running and main_thread.is_alive():
            main_thread.join(timeout=0.5)
        main_thread.stop()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        fteproxy.fatal_error("Main thread terminated unexpectedly: "+str(e))
    finally:
        if fteproxy.conf.getValue('runtime.mode'):
            pid_file = get_pid_file()

            if pid_file and os.path.exists(pid_file):
                os.unlink(pid_file)
