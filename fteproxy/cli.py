#!/usr/bin/env python3
# -*- coding: utf-8 -*-




import sys
import os
import signal
import glob
import argparse
import threading
import traceback

import fteproxy
import fteproxy.conf
import fteproxy.server
import fteproxy.client

FTEPROXY_VERSION = fteproxy.__version__


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

    def init_cipher(self, stream_format):

        key = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')

        try:
            pattern = fteproxy.defs.getRegex(stream_format)
        except fteproxy.defs.InvalidRegexName:
            fteproxy.fatal_error('Invalid format name ' + stream_format)

        length = fteproxy.defs.getLength(stream_format)
        # Build the cipher to validate the format is usable with this key.
        # libfte 0.4 raises FormatCapacityError here if the format is too small
        # to carry the cipher's frame overhead.
        fteproxy._make_cipher(pattern, length, key)

    def do_client(self):

        FTEMain.init_cipher(self, self._args.downstream_format)
        FTEMain.init_cipher(self, self._args.upstream_format)
        warn_if_default_key()

        if not self._args.quiet:
            print('Client ready!')

        self._client = FTEMain.init_listener(self, 'client')
        self._client.daemon = True
        self._client.start()
        self._client.join()

    def do_server(self):

        languages = fteproxy.defs.load_definitions()
        for language in languages.keys():
            FTEMain.init_cipher(self, language)
        warn_if_default_key()

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


def warn_if_default_key():
    """Warn when the built-in default key is in use.

    libfte 0.4 requires a key, and fteproxy falls back to the constant in
    ``fteproxy.conf`` when neither ``--key`` nor ``--key-file`` is given. That
    key is public, so anyone can read and forge the tunnel's traffic.
    """
    if fteproxy.conf.getValue('runtime.fteproxy.encrypter.key') == fteproxy.conf.DEFAULT_KEY:
        fteproxy.warn('using the built-in default key, which is public: pass '
                      '--key or --key-file with a secret shared by both endpoints')


def parse_hex_key(hex_key):
    """Validate a hex-encoded key and return it as bytes.

    The key must be exactly 64 hexadecimal characters (a 32-byte key).
    Surrounding whitespace is ignored so keys read from a file may end in a
    trailing newline. Exits the process with an error on invalid input.
    """
    hex_key = hex_key.strip()
    if len(hex_key) != 64:
        fteproxy.warn('Invalid key length: ' + str(len(hex_key))
                      + ', should be 64')
        sys.exit(1)
    try:
        return bytes.fromhex(hex_key)
    except ValueError:
        fteproxy.warn('Invalid key format, must contain only 0-9a-fA-F')
        sys.exit(1)


def read_key_file(path):
    """Read a hex-encoded key from a file and return it as bytes.

    Storing the key in a file keeps it out of shell history and process
    listings (e.g., ``ps``), unlike passing it via ``--key``. Exits the
    process with an error if the file cannot be read or holds an invalid key.
    """
    try:
        with open(path) as key_file:
            contents = key_file.read()
    except IOError as e:
        fteproxy.warn('Failed to read key file "' + str(path) + '": ' + str(e))
        sys.exit(1)
    return parse_hex_key(contents)


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
                "--record-layer-mode":  "runtime.fteproxy.record_layer.mode",
            }

            if self.dest == "key_file":
                setattr(namespace, self.dest, values)
                fteproxy.conf.setValue('runtime.fteproxy.encrypter.key',
                                       read_key_file(values))
                return

            if self.dest == "key":
                values = parse_hex_key(values)

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
                        metavar='(client|server)',
                        choices=['client', 'server'],
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
    parser.add_argument('--record-layer-mode', action=setConfValue,
                        metavar='(format|hybrid)',
                        choices=['format', 'hybrid'],
                        help='Record framing. "hybrid" (default) formats a '
                             'header per record and sends the body as raw '
                             'bytes: fast, but only the header blends in with '
                             'the target protocol. "format" transforms every '
                             'byte into the format for full-stream realism at '
                             'much lower throughput. Both endpoints must match.',
                        default=fteproxy.conf.getValue(
                            'runtime.fteproxy.record_layer.mode'))
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument('--key', action=setConfValue,
                        help='Cryptographic key, hex, must be exactly 64 characters',
                        default=fteproxy.conf.getValue('runtime.fteproxy.encrypter.key'
                                                  ).hex())
    key_group.add_argument('--key-file', action=setConfValue, dest='key_file',
                        metavar='PATH', default=None,
                        help='Path to a file containing the cryptographic key '
                             '(64 hex characters). Use instead of --key to keep '
                             'the key out of shell history and process listings.')
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
