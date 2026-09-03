#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The fteproxy command line.

Both ``python -m fteproxy`` and the ``fteproxy`` console script call
:func:`main`, which returns a process exit status:

===  ==========================================================
  0  clean shutdown
  1  runtime failure (bad format name, unusable key, bind refused)
  2  usage error (argparse rejected the command line, or a required
     argument is missing)
===  ==========================================================

Parsing is a plain ``argparse`` parse followed by one
:func:`apply_args_to_conf` step. The previous ``setConfValue`` action wrote
``fteproxy.conf`` as a side effect of parsing, which meant a value that came
from a default never reached the configuration at all (argparse does not run
actions for defaults). That is why a no-argument run used to die with a
``TypeError`` deep in the relay, and why it still exited 0.
"""

import argparse
import glob
import logging
import os
import signal
import sys
import threading

import fteproxy
import fteproxy.conf
import fteproxy.defs
import fteproxy.server
import fteproxy.client

FTEPROXY_VERSION = fteproxy.__version__

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

_LICENSE_BANNER = """fteproxy %s
Copyright (C) 2012-2026 Kevin P. Dyer <kpdyer@gmail.com>
This program comes with ABSOLUTELY NO WARRANTY. This is free software, and
you are welcome to redistribute it under certain conditions.""" % FTEPROXY_VERSION


class _PrintVersion(argparse.Action):
    """``--version``: the version and the licence notice, unwrapped.

    argparse's own ``version`` action runs the text through the help
    formatter, which reflows the notice into a paragraph. The notice used to
    be a banner printed on every run; it lives here now.
    """

    def __init__(self, option_strings, dest, **kwargs):
        kwargs.setdefault('nargs', 0)
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print(_LICENSE_BANNER)
        parser.exit(EXIT_OK)


class UsageError(Exception):
    """The command line parsed, but one of its values cannot be used.

    Reported like any other argparse error: the message on stderr and exit
    status 2.
    """


class StartupError(Exception):
    """A resource the run needs could not be obtained: an unknown format name,
    a format the key cannot drive, or a port that will not bind. Exit status 1.
    """


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

def configure_logging(quiet=False, verbose=False):
    """Point the ``fteproxy`` logger at stderr and set its level.

    Default INFO, ``-q`` ERROR, ``-v`` DEBUG. stderr, not stdout, so that a
    command whose stdout is data (``fteproxy formats``) stays pipeable.
    """
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))

    logger = fteproxy.logger
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
    logger.addHandler(handler)
    logger.setLevel(level)
    # Do not let fteproxy's records reach a root handler an embedding program
    # installed; the CLI owns the process's stderr.
    logger.propagate = False
    return level


# --------------------------------------------------------------------------- #
# Keys
# --------------------------------------------------------------------------- #

def parse_hex_key(hex_key):
    """Validate a hex-encoded key and return it as bytes.

    The key must be exactly 64 hexadecimal characters (a 32-byte key).
    Surrounding whitespace is ignored so keys read from a file may end in a
    trailing newline. Raises :class:`UsageError` on invalid input; the message
    never contains the key material.
    """
    hex_key = hex_key.strip()
    if len(hex_key) != 64:
        raise UsageError('invalid key length: %d hex characters, expected 64'
                         % len(hex_key))
    try:
        return bytes.fromhex(hex_key)
    except ValueError:
        raise UsageError('invalid key format: must contain only 0-9a-fA-F')


def read_key_file(path):
    """Read a hex-encoded key from a file and return it as bytes.

    Storing the key in a file keeps it out of shell history and process
    listings (e.g., ``ps``), unlike passing it via ``--key``. Raises
    :class:`UsageError` if the file cannot be read or holds an invalid key.
    """
    try:
        with open(path) as key_file:
            contents = key_file.read()
    except OSError as e:
        raise UsageError('failed to read key file "%s": %s' % (path, e))
    return parse_hex_key(contents)


def warn_if_default_key():
    """Warn when the built-in default key is in use.

    libfte 0.4 requires a key, and fteproxy falls back to the constant in
    ``fteproxy.conf`` when neither ``--key`` nor ``--key-file`` is given. That
    key is public, so anyone can read and forge the tunnel's traffic.
    """
    if fteproxy.conf.getValue('runtime.fteproxy.encrypter.key') == fteproxy.conf.DEFAULT_KEY:
        fteproxy.warn('using the built-in default key, which is public: pass '
                      '--key or --key-file with a secret shared by both endpoints')


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #

def build_parser():
    """Build the argument parser.

    One flat command (the relay, selected with ``--mode``) plus subcommands.
    ``formats`` is the first subcommand; the 0.4 command line replaces the flat
    interface with ``server``/``client``/``keygen`` alongside it.
    """
    parser = argparse.ArgumentParser(
        prog='fteproxy',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--version', action=_PrintVersion,
                        help='Output the version of fteproxy, then quit.')
    parser.add_argument('--mode', default=None,
                        metavar='(client|server)',
                        choices=['client', 'server'],
                        help='Relay mode: client or server')
    parser.add_argument('--stop', action='store_true',
                        help='Shutdown daemon process')
    parser.add_argument('--upstream-format', dest='upstream_format',
                        help='Client-to-server language format',
                        default=fteproxy.conf.getValue('runtime.state.upstream_language'))
    parser.add_argument('--downstream-format', dest='downstream_format',
                        help='Server-to-client language format',
                        default=fteproxy.conf.getValue('runtime.state.downstream_language'))
    parser.add_argument('--client_ip',
                        help='Client-side listening IP',
                        default=fteproxy.conf.getValue('runtime.client.ip'))
    parser.add_argument('--client_port', type=int,
                        help='Client-side listening port',
                        default=fteproxy.conf.getValue('runtime.client.port'))
    parser.add_argument('--server_ip',
                        help='Server-side listening IP',
                        default=fteproxy.conf.getValue('runtime.server.ip'))
    parser.add_argument('--server_port', type=int,
                        help='Server-side listening port',
                        default=fteproxy.conf.getValue('runtime.server.port'))
    parser.add_argument('--proxy_ip',
                        help='Forwarding-proxy listening IP',
                        default=fteproxy.conf.getValue('runtime.proxy.ip'))
    parser.add_argument('--proxy_port', type=int,
                        help='Forwarding-proxy listening port',
                        default=fteproxy.conf.getValue('runtime.proxy.port'))
    parser.add_argument('--release',
                        help='Definitions file to use, specified as YYYYMMDD',
                        default=fteproxy.conf.getValue('fteproxy.defs.release'))
    parser.add_argument('--record-layer-mode', dest='record_layer_mode',
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

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument('-q', '--quiet', action='store_true',
                           help='Log errors only.')
    verbosity.add_argument('-v', '--verbose', action='store_true',
                           help='Log per-connection detail.')

    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument('--key',
                           help='Shared secret, hex, exactly 64 characters; must '
                                'match on both endpoints. The built-in default '
                                'is public and gives no protection: always '
                                'supply your own (see --key-file).',
                           default=fteproxy.conf.getValue(
                               'runtime.fteproxy.encrypter.key').hex())
    key_group.add_argument('--key-file', dest='key_file',
                           metavar='PATH', default=None,
                           help='Path to a file containing the cryptographic key '
                                '(64 hex characters). Use instead of --key to keep '
                                'the key out of shell history and process listings.')

    subparsers = parser.add_subparsers(dest='command', metavar='COMMAND')
    formats_parser = subparsers.add_parser(
        'formats',
        help='List the formats in a definitions file, then quit.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    # SUPPRESS so that "fteproxy --release X formats" keeps the value given
    # before the subcommand; a subparser default would otherwise overwrite it.
    formats_parser.add_argument('--release', default=argparse.SUPPRESS,
                                help='Definitions file to list, as YYYYMMDD')

    return parser


def apply_args_to_conf(args):
    """Copy every parsed argument into ``fteproxy.conf``, defaults included.

    One step, run after parsing, so the configuration a run sees is exactly
    what the command line says, whether a value was typed or defaulted.
    """
    conf = fteproxy.conf
    conf.setValue('runtime.mode', args.mode)
    conf.setValue('runtime.client.ip', args.client_ip)
    conf.setValue('runtime.client.port', args.client_port)
    conf.setValue('runtime.server.ip', args.server_ip)
    conf.setValue('runtime.server.port', args.server_port)
    conf.setValue('runtime.proxy.ip', args.proxy_ip)
    conf.setValue('runtime.proxy.port', args.proxy_port)
    conf.setValue('runtime.state.upstream_language', args.upstream_format)
    conf.setValue('runtime.state.downstream_language', args.downstream_format)
    conf.setValue('runtime.fteproxy.record_layer.mode', args.record_layer_mode)

    if conf.getValue('fteproxy.defs.release') != args.release:
        conf.setValue('fteproxy.defs.release', args.release)
        fteproxy.defs._definitions = None

    if args.key_file is not None:
        conf.setValue('runtime.fteproxy.encrypter.key', read_key_file(args.key_file))
    else:
        conf.setValue('runtime.fteproxy.encrypter.key', parse_hex_key(args.key))


# --------------------------------------------------------------------------- #
# Startup validation
# --------------------------------------------------------------------------- #

def check_format(format_name):
    """Build the cipher for ``format_name`` so an unusable format fails now.

    libfte raises ``FormatCapacityError`` when a format is too small to carry
    the cipher's frame, and the definitions lookup raises for an unknown name.
    Both used to surface only on the first connection, as a client-side
    timeout.
    """
    try:
        pattern = fteproxy.defs.getRegex(format_name)
    except fteproxy.defs.InvalidRegexName:
        raise StartupError('invalid format name: ' + format_name)
    except OSError as e:
        raise StartupError('failed to read the definitions file: ' + str(e))

    length = fteproxy.defs.getLength(format_name)
    key = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')
    try:
        fteproxy._make_cipher(pattern, length, key)
    except Exception as e:
        raise StartupError('format %s is unusable: %s' % (format_name, e))


def check_startup(mode):
    """Validate every format this role will use, before anything is printed,
    bound, or written to disk."""
    if mode == 'client':
        check_format(fteproxy.conf.getValue('runtime.state.upstream_language'))
        check_format(fteproxy.conf.getValue('runtime.state.downstream_language'))
    else:
        try:
            definitions = fteproxy.defs.load_definitions()
        except OSError as e:
            raise StartupError('failed to read the definitions file: ' + str(e))
        # The server accepts any format the client asks for, so all of them
        # have to work here.
        for format_name in definitions.keys():
            check_format(format_name)
    warn_if_default_key()


# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #

def do_formats(args):
    """Print each base format name with its covertext length and capacity.

    A base name is what the two directions share: ``manual-http`` covers
    ``manual-http-request`` and ``manual-http-response``. The capacity is how
    many bytes of message one covertext of that length carries, which is what
    bounds a record.
    """
    try:
        definitions = fteproxy.defs.load_definitions()
    except OSError as e:
        fteproxy.warn('failed to read the definitions file: ' + str(e))
        return EXIT_FAILURE

    default_base = _base_name(
        fteproxy.conf.getValue('runtime.state.upstream_language'))
    key = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')

    bases = {}
    for name in definitions:
        base = _base_name(name)
        direction = name[len(base) + 1:] if name != base else ''
        if direction not in ('request', 'response'):
            continue
        bases.setdefault(base, {})[direction] = name

    rows = []
    for base in sorted(bases):
        row = [base]
        for direction in ('request', 'response'):
            name = bases[base].get(direction)
            if name is None:
                row += ['-', '-']
                continue
            length = fteproxy.defs.getLength(name)
            try:
                capacity = fteproxy._make_cipher(
                    fteproxy.defs.getRegex(name), length, key).max_plaintext_bytes
            except Exception:
                row += [str(length), 'unusable']
                continue
            row += [str(length), str(capacity)]
        row.append('(default)' if base == default_base else '')
        rows.append(row)

    header = ['name', 'req len', 'req cap', 'resp len', 'resp cap', '']
    widths = [max(len(r[i]) for r in [header] + rows) for i in range(len(header))]
    print('definitions release %s'
          % fteproxy.conf.getValue('fteproxy.defs.release'))
    print('covertext length and message capacity, in bytes, per direction')
    print()
    for row in [header] + rows:
        line = '  '.join(cell.ljust(widths[i]) if i == 0 else cell.rjust(widths[i])
                         for i, cell in enumerate(row))
        print(line.rstrip())
    return EXIT_OK


def _base_name(format_name):
    """``manual-http-request`` -> ``manual-http``."""
    for suffix in ('-request', '-response'):
        if format_name.endswith(suffix):
            return format_name[:-len(suffix)]
    return format_name


# --------------------------------------------------------------------------- #
# PID files (removed with --stop in the 0.4 command line)
# --------------------------------------------------------------------------- #

def get_pid_file():
    return os.path.join(
        fteproxy.conf.getValue('general.pid_dir'),
        '.' + str(fteproxy.conf.getValue('runtime.mode'))
        + '-' + str(os.getpid()) + '.pid')


def write_pid_file():
    pid_file = get_pid_file()
    try:
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
    except OSError:
        fteproxy.warn('failed to write PID file to disk: ' + pid_file)
        return None
    return pid_file


def do_stop(mode):
    """Signal every running fteproxy of ``mode`` recorded in the PID directory."""
    pattern = os.path.join(fteproxy.conf.getValue('general.pid_dir'),
                           '.' + mode + '-*.pid')
    for pid_file in glob.glob(pattern):
        try:
            with open(pid_file) as f:
                pid = int(f.read())
        except (OSError, ValueError):
            fteproxy.warn('failed to read PID file: ' + pid_file)
            continue
        try:
            os.kill(pid, signal.SIGINT)
        except OSError:
            fteproxy.warn('failed to signal process ' + str(pid))
        try:
            os.unlink(pid_file)
        except OSError:
            fteproxy.warn('failed to remove PID file: ' + pid_file)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# The relay
# --------------------------------------------------------------------------- #

def init_listener(mode):
    server_ip = fteproxy.conf.getValue('runtime.server.ip')
    server_port = fteproxy.conf.getValue('runtime.server.port')
    if mode == 'client':
        return fteproxy.client.listener(
            fteproxy.conf.getValue('runtime.client.ip'),
            fteproxy.conf.getValue('runtime.client.port'),
            server_ip, server_port)
    return fteproxy.server.listener(
        server_ip, server_port,
        fteproxy.conf.getValue('runtime.proxy.ip'),
        fteproxy.conf.getValue('runtime.proxy.port'))


def run_relay(mode):
    """Bind, then relay until SIGINT or SIGTERM. Returns the exit status.

    The bind happens on this thread so a refused port is a startup failure with
    a non-zero status, not a listener thread that dies while the process goes
    on to exit 0.
    """
    listener = init_listener(mode)
    try:
        listener.bind()
    except OSError as e:
        raise StartupError('failed to bind %s: %s'
                           % (_bind_address(mode), e))

    pid_file = write_pid_file()

    stopping = threading.Event()

    def _stop(signum, frame):
        stopping.set()

    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            previous[signum] = signal.signal(signum, _stop)
        except ValueError:
            # Not the main thread (an embedding program calling main()).
            pass

    listener.daemon = True
    listener.start()
    fteproxy.info('%s listening on %s' % (mode, _bind_address(mode)))
    try:
        while listener.is_alive() and not stopping.is_set():
            stopping.wait(0.5)
    finally:
        listener.stop()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        if pid_file and os.path.exists(pid_file):
            try:
                os.unlink(pid_file)
            except OSError:
                pass
    return EXIT_OK


def _bind_address(mode):
    if mode == 'client':
        return '%s:%d' % (fteproxy.conf.getValue('runtime.client.ip'),
                          fteproxy.conf.getValue('runtime.client.port'))
    return '%s:%d' % (fteproxy.conf.getValue('runtime.server.ip'),
                      fteproxy.conf.getValue('runtime.server.port'))


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main(argv=None):
    """Parse ``argv``, run the requested command, and return an exit status."""
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    configure_logging(quiet=args.quiet, verbose=args.verbose)

    try:
        apply_args_to_conf(args)
    except UsageError as e:
        parser.error(str(e))  # exits 2

    if args.command == 'formats':
        return do_formats(args)

    if args.mode is None:
        parser.print_usage(sys.stderr)
        print('fteproxy: --mode (client|server) is required, '
              'or name a subcommand (formats).', file=sys.stderr)
        return EXIT_USAGE

    if args.stop:
        return do_stop(args.mode)

    try:
        check_startup(args.mode)
        return run_relay(args.mode)
    except StartupError as e:
        fteproxy.logger.error(str(e))
        return EXIT_FAILURE
    except KeyboardInterrupt:
        return EXIT_OK
