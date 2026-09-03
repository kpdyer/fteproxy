#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The fteproxy command line.

Four subcommands::

    fteproxy server  [--listen [HOST]:PORT] [--allow RULE]... [--advertise HOST[:PORT]]
                     [--state-dir DIR] [--defs RELEASE] [-q | -v]
    fteproxy client  [URI] [-D [BIND:]PORT] [-L [BIND:]PORT:HOST:PORT]...
                     [--format NAME] [--mode hybrid|format] [--no-check]
                     [--state-dir DIR] [-q | -v]
    fteproxy keygen  [--state-dir DIR] [--advertise HOST[:PORT]]
    fteproxy formats [--defs RELEASE]

Both ``python -m fteproxy`` and the ``fteproxy`` console script call
:func:`main`, which returns a process exit status:

===  ==========================================================
  0  clean shutdown
  1  runtime failure (bad format name, unusable key, bind refused,
     a startup check that could not reach the server)
  2  usage error
===  ==========================================================

Command output -- a connection string, the format table -- goes to stdout, so
it can be piped. Everything else goes to stderr through the ``fteproxy``
logger, which carries a redaction filter so that no key, server-id or
connection string can reach a log file.
"""

import argparse
import logging
import signal
import sys
import threading

import fteproxy
import fteproxy.conf
import fteproxy.config
import fteproxy.defs
import fteproxy.relay
import fteproxy.stream

FTEPROXY_VERSION = fteproxy.__version__

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

DEFAULT_LISTEN = ':8080'
DEFAULT_SOCKS = '127.0.0.1:1080'
DEFAULT_FORMAT = 'manual-http'
DEFAULT_MODE = 'hybrid'

SUBCOMMANDS = ('server', 'client', 'keygen', 'formats')

#: Flags from the pre-1.0 command line. They are recognised only so that a
#: script carrying one gets a pointer instead of "unrecognized arguments", and
#: are never aliased: the destination is chosen on the client now and the
#: shared key is gone, so a silent alias would run a different topology than
#: the operator asked for.
REMOVED_FLAGS = (
    '--mode', '--stop', '--quiet', '--key', '--key-file', '--release',
    '--client_ip', '--client_port', '--server_ip', '--server_port',
    '--proxy_ip', '--proxy_port',
    '--upstream-format', '--downstream-format', '--record-layer-mode',
)

_LICENSE_BANNER = """fteproxy %s
Copyright (C) 2012-2026 Kevin P. Dyer <kpdyer@gmail.com>
This program comes with ABSOLUTELY NO WARRANTY. This is free software, and
you are welcome to redistribute it under certain conditions.""" % FTEPROXY_VERSION

_UPGRADE_POINTER = (
    "fteproxy: %s was removed in 1.0. The destination is chosen on the client "
    "now and the shared key is replaced by a connection string, so the old "
    "flags would run a different topology than you asked for. See 'Upgrading "
    "to 1.0.0' in the README.")


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

    Reported like any other argparse error: the message on stderr, exit 2.
    """


class StartupError(Exception):
    """A resource the run needs could not be obtained: an unknown format, a
    key that cannot be read, a port that will not bind, or a server the
    startup check could not reach. Exit status 1.
    """


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

def configure_logging(quiet=False, verbose=False):
    """Point the ``fteproxy`` logger at stderr and set its level.

    Default INFO, ``-q`` ERROR, ``-v`` DEBUG. The package logger already
    carries :class:`fteproxy.RedactingFilter`, so a key or a connection string
    that reaches a message is stripped before any handler sees it.
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


def _report(args, message, stream=None):
    """Progress for a person, on stderr, silenced by ``-q``."""
    if getattr(args, 'quiet', False):
        return
    print(message, file=stream or sys.stderr)


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #

def _verbosity(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-q', action='store_true', dest='quiet',
                       help='Log errors only.')
    group.add_argument('-v', action='store_true', dest='verbose',
                       help='Log per-connection detail.')


def _state_dir_flag(parser):
    parser.add_argument('--state-dir', metavar='DIR', default=None,
                        help='Where server.key and connection.txt live '
                             '(default: $FTEPROXY_STATE_DIR, then '
                             '$XDG_STATE_HOME/fteproxy, then '
                             '~/.local/state/fteproxy).')


def build_parser():
    parser = argparse.ArgumentParser(
        prog='fteproxy',
        description='A format-transforming-encryption tunnel.')
    parser.add_argument('--version', action=_PrintVersion,
                        help='Print the version and licence, then quit.')
    subparsers = parser.add_subparsers(dest='command', metavar='COMMAND')

    server = subparsers.add_parser(
        'server', help='Accept tunnelled connections and dial where they ask.')
    server.add_argument('--listen', metavar='[HOST]:PORT', default=DEFAULT_LISTEN,
                        help='Address to listen on. ":PORT" means every '
                             'interface; IPv6 literals go in brackets.')
    server.add_argument('--allow', metavar='RULE', action='append', default=[],
                        help='A destination clients may reach: "any", '
                             'HOST[:PORT], CIDR[:PORT] or *.example.com[:PORT]. '
                             'Repeatable. Without any rule the policy is every '
                             'destination except this host\'s loopback and '
                             'link-local addresses.')
    server.add_argument('--advertise', metavar='HOST[:PORT]', default=None,
                        help='The address to put in the connection string. '
                             'Without it the string carries a placeholder for '
                             'you to fill in.')
    server.add_argument('--defs', metavar='RELEASE',
                        default=fteproxy.conf.getValue('fteproxy.defs.release'),
                        help='Definitions release to serve, as YYYYMMDD.')
    _state_dir_flag(server)
    _verbosity(server)

    client = subparsers.add_parser(
        'client', help='Listen locally and tunnel to an fteproxy server.')
    client.add_argument('uri', nargs='?', metavar='URI', default=None,
                        help='fte://SERVER-ID@HOST:PORT. Falls back to '
                             '$FTEPROXY_URI, then connection.txt in the state '
                             'directory.')
    client.add_argument('-D', metavar='[BIND:]PORT', action='append',
                        dest='socks', default=[],
                        help='SOCKS5 listener. The default when neither -D nor '
                             '-L is given is ' + DEFAULT_SOCKS + '.')
    client.add_argument('-L', metavar='[BIND:]PORT:HOST:PORT', action='append',
                        dest='forwards', default=[],
                        help='Forward a local port to one destination through '
                             'the tunnel. Repeatable.')
    client.add_argument('--format', metavar='NAME', default=None,
                        help='Base format name; see "fteproxy formats" '
                             '(default: the URI\'s hint, else %s).'
                             % DEFAULT_FORMAT)
    client.add_argument('--mode', choices=['hybrid', 'format'], default=None,
                        help='Record framing. "hybrid" formats a header per '
                             'record and sends the body as raw authenticated '
                             'bytes: fast, but only the header blends in with '
                             'the target protocol. "format" transforms every '
                             'byte for full-stream realism at much lower '
                             'throughput (default: the URI\'s hint, else %s).'
                             % DEFAULT_MODE)
    client.add_argument('--no-check', action='store_true',
                        help='Skip the startup check, which otherwise opens '
                             'one short session so a bad connection string '
                             'fails now instead of on first use.')
    _state_dir_flag(client)
    _verbosity(client)

    keygen = subparsers.add_parser(
        'keygen', help='Create server.key if absent and print the connection '
                       'string.')
    keygen.add_argument('--advertise', metavar='HOST[:PORT]', default=None,
                        help='The address to put in the connection string.')
    _state_dir_flag(keygen)
    _verbosity(keygen)

    formats = subparsers.add_parser(
        'formats', help='List the formats in a definitions file.')
    formats.add_argument('--defs', metavar='RELEASE',
                         default=fteproxy.conf.getValue('fteproxy.defs.release'),
                         help='Definitions release to list, as YYYYMMDD.')
    _verbosity(formats)

    return parser


def removed_flag(argv):
    """The first pre-1.0 flag in ``argv``, or None.

    Only the part before a subcommand is scanned, because ``--mode`` means
    something else under ``client``.
    """
    head = argv
    for index, token in enumerate(argv):
        if token in SUBCOMMANDS:
            head = argv[:index]
            break
    for token in head:
        name = token.split('=', 1)[0]
        if name in REMOVED_FLAGS:
            return name
    return None


# --------------------------------------------------------------------------- #
# Shared startup
# --------------------------------------------------------------------------- #

def select_defs(release):
    """Point the definitions loader at ``release`` and load it now.

    Loading validates every format in the file, so a release that cannot carry
    a handshake fails here rather than as a client that hangs.
    """
    if fteproxy.conf.getValue('fteproxy.defs.release') != release:
        fteproxy.conf.setValue('fteproxy.defs.release', release)
        fteproxy.defs._definitions = None
    try:
        return fteproxy.defs.load_definitions()
    except (OSError, fteproxy.defs.DefinitionsError) as e:
        raise StartupError('cannot load definitions release %s: %s'
                           % (release, e))


def check_format(base):
    """Build both directions of ``base`` so an unusable format fails now."""
    try:
        request, response = fteproxy.defs.getRegex(base + '-request'), \
            fteproxy.defs.getRegex(base + '-response')
    except fteproxy.defs.InvalidRegexName:
        raise StartupError(
            'unknown format %r; "fteproxy formats" lists the base names' % base)
    for name, pattern in ((base + '-request', request),
                          (base + '-response', response)):
        try:
            fteproxy._regex_format(pattern, fteproxy.defs.getLength(name))
        except Exception as e:
            raise StartupError('format %s is unusable: %s' % (name, e))


def resolve_state_dir(args, create=True):
    directory = fteproxy.config.state_dir(getattr(args, 'state_dir', None))
    if create:
        fteproxy.config.ensure_state_dir(directory)
    return directory


def parse_advertise(text, default_port):
    try:
        host, port = fteproxy.config.split_host_port(
            text, default_port=default_port)
    except ValueError as e:
        raise UsageError('--advertise %s' % e)
    if not host:
        raise UsageError('--advertise needs a host')
    return host, port


# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #

def do_keygen(args):
    directory = resolve_state_dir(args)
    private, public, created = fteproxy.config.ensure_server_key(directory)
    del private

    host, port = fteproxy.config.HOST_PLACEHOLDER, fteproxy.config.DEFAULT_PORT
    if args.advertise:
        host, port = parse_advertise(args.advertise, fteproxy.config.DEFAULT_PORT)
    uri = fteproxy.config.ConnectionString(public, host, port)
    path = fteproxy.config.write_connection_string(directory, uri)

    _report(args, '%s %s'
            % ('wrote' if created else 'kept',
               fteproxy.config.server_key_path(directory)))
    _report(args, 'connection string also written to %s' % path)
    print(uri.format())
    return EXIT_OK


def do_formats(args):
    """Print each base format name with its covertext length and capacity.

    A base name is what the two directions share: ``manual-http`` covers
    ``manual-http-request`` and ``manual-http-response``. The capacity is how
    many bytes of message one covertext of that length carries, which is what
    bounds a record.
    """
    try:
        definitions = select_defs(args.defs)
    except StartupError as e:
        fteproxy.logger.error(str(e))
        return EXIT_FAILURE

    key = b'\x00' * 32
    bases = {}
    for name in definitions:
        base = fteproxy.defs.base_name(name)
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
                    fteproxy.defs.getRegex(name), length,
                    key).max_plaintext_bytes
            except Exception:
                row += [str(length), 'unusable']
                continue
            row += [str(length), str(capacity)]
        row.append('(default)' if base == DEFAULT_FORMAT else '')
        rows.append(row)

    header = ['name', 'req len', 'req cap', 'resp len', 'resp cap', '']
    widths = [max(len(r[i]) for r in [header] + rows) for i in range(len(header))]
    print('definitions release %s' % args.defs)
    print('covertext length and message capacity, in bytes, per direction')
    print()
    for row in [header] + rows:
        line = '  '.join(cell.ljust(widths[i]) if i == 0 else cell.rjust(widths[i])
                         for i, cell in enumerate(row))
        print(line.rstrip())
    return EXIT_OK


def do_server(args):
    select_defs(args.defs)
    directory = resolve_state_dir(args)
    private, public, created = fteproxy.config.ensure_server_key(directory)

    try:
        host, port = fteproxy.config.split_host_port(args.listen)
    except ValueError as e:
        raise UsageError('--listen %s' % e)

    try:
        rules = fteproxy.stream.AllowRules(args.allow)
    except fteproxy.stream.InvalidRule as e:
        raise UsageError(str(e))

    advertise_host, advertise_port = fteproxy.config.HOST_PLACEHOLDER, port
    if args.advertise:
        advertise_host, advertise_port = parse_advertise(args.advertise, port)
    uri = fteproxy.config.ConnectionString(public, advertise_host,
                                           advertise_port,
                                           defs=str(args.defs))
    connection_file = fteproxy.config.write_connection_string(directory, uri)

    listener = fteproxy.relay.ServerListener(host, port, private, rules=rules)
    try:
        listener.bind()
    except OSError as e:
        raise StartupError('cannot listen on %s: %s' % (args.listen, e))

    bound_host, bound_port = listener.address
    _report(args, 'listening on %s' % _render_address(bound_host, bound_port))
    if not args.quiet:
        print('key: %s%s' % (fteproxy.config.server_key_path(directory),
                             ' (created)' if created else ''))
        print('allowing: %s' % rules.describe())
        print('clients connect with:')
        print('  fteproxy client %s' % uri.format())
        print('(also written to %s)' % connection_file)
        sys.stdout.flush()
    return serve_forever([listener])


def do_client(args):
    directory = resolve_state_dir(args, create=False)
    try:
        uri, source = fteproxy.config.resolve_client_uri(args.uri, directory)
    except fteproxy.config.ConfigError as e:
        raise UsageError(str(e))
    if uri is None:
        raise UsageError(
            'no connection string. Pass one as an argument, set %s, or run '
            'the server once so it writes %s.'
            % (fteproxy.config.ENV_URI,
               fteproxy.config.connection_path(directory)))
    fteproxy.debug('connection string from %s' % source)

    # The definitions release is the server operator's to choose: the client
    # takes it from the URI's hint, since a mismatch is refused at the far end.
    defs = uri.defs or fteproxy.conf.getValue('fteproxy.defs.release')
    select_defs(str(defs))

    # Flags beat the URI's hints, which beat the built-in defaults.
    base = args.format or uri.format_name or DEFAULT_FORMAT
    mode = args.mode or uri.mode or DEFAULT_MODE
    check_format(base)

    try:
        socks_specs = [fteproxy.config.split_socks_spec(spec)
                       for spec in args.socks]
        forwards = [fteproxy.config.split_forward_spec(spec)
                    for spec in args.forwards]
    except ValueError as e:
        raise UsageError(str(e))
    if not socks_specs and not forwards:
        socks_specs = [fteproxy.config.split_socks_spec(DEFAULT_SOCKS)]

    common = dict(server_address=uri.address, server_id=uri.server_id,
                  format=base, mode=mode, defs=str(defs))

    listeners = []
    for bind, port in socks_specs:
        listeners.append(fteproxy.relay.SocksListener(bind, port, **common))
    for (bind, port), destination in forwards:
        listeners.append(fteproxy.relay.ForwardListener(
            bind, port, destination=destination, **common))

    if not args.no_check and not run_startup_check(args, listeners[0], uri):
        return EXIT_FAILURE

    for listener in listeners:
        try:
            listener.bind()
        except OSError as e:
            for started in listeners:
                started.stop()
            raise StartupError('cannot listen on %s: %s'
                               % (_render_address(*listener.address), e))

    for listener, spec in zip(listeners,
                              [('SOCKS5', None) for _ in socks_specs]
                              + [('forward', destination)
                                 for _, destination in forwards]):
        kind, destination = spec
        where = _render_address(*listener.address)
        if destination is None:
            _report(args, 'SOCKS5 on %s' % where)
        else:
            _report(args, 'forwarding %s to %s through the tunnel'
                    % (where, _render_address(*destination)))
    return serve_forever(listeners)


def run_startup_check(args, listener, uri):
    """Open one short session so a bad connection string fails now.

    On the wire it is an ordinary session start, and it costs one round trip.
    The alternative is a first connection that hangs until a timeout with
    nothing to say about why. Returns False when the check failed, having said
    so; the caller exits 1.

    Reported here rather than raised, so that the outcome finishes the
    "checking ..." line the operator is already looking at instead of arriving
    as a separate log record.
    """
    prefix = 'checking %s ... ' % _render_address(uri.host, uri.port)
    if not args.quiet:
        sys.stderr.write(prefix)
        sys.stderr.flush()
    try:
        format_name, mode = listener.check()
    except Exception as e:
        if args.quiet:
            sys.stderr.write(prefix)
        sys.stderr.write('failed: %s\n' % e)
        sys.stderr.write('  (wrong connection string, or the server is not '
                         'running fteproxy 1.0)\n')
        sys.stderr.flush()
        return False
    if not args.quiet:
        sys.stderr.write('ok (protocol %d, %s, %s)\n'
                         % (fteproxy.handshake.PROTOCOL_VERSION, format_name,
                            mode))
        sys.stderr.flush()
    return True


def _render_address(host, port):
    if not host:
        return '[::]:%d' % port
    return '[%s]:%d' % (host, port) if ':' in host else '%s:%d' % (host, port)


# --------------------------------------------------------------------------- #
# Running
# --------------------------------------------------------------------------- #

def serve_forever(listeners):
    """Run ``listeners`` in the foreground until SIGINT or SIGTERM.

    No PID file and no ``--stop``: the process runs in the foreground and a
    service manager, a shell job or a container runtime stops it the way it
    stops anything else.
    """
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

    for listener in listeners:
        listener.daemon = True
        listener.start()
    try:
        while not stopping.is_set() and any(l.is_alive() for l in listeners):
            stopping.wait(0.5)
    finally:
        for listener in listeners:
            listener.stop()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

_COMMANDS = {
    'server': do_server,
    'client': do_client,
    'keygen': do_keygen,
    'formats': do_formats,
}


def main(argv=None):
    """Parse ``argv``, run the requested command, and return an exit status."""
    argv = sys.argv[1:] if argv is None else list(argv)

    removed = removed_flag(argv)
    if removed is not None:
        print(_UPGRADE_POINTER % removed, file=sys.stderr)
        return EXIT_USAGE

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    configure_logging(quiet=args.quiet, verbose=args.verbose)

    try:
        return _COMMANDS[args.command](args)
    except UsageError as e:
        parser.error(str(e))  # exits 2
    except (StartupError, fteproxy.config.ConfigError) as e:
        fteproxy.logger.error(str(e))
        return EXIT_FAILURE
    except KeyboardInterrupt:
        return EXIT_OK
