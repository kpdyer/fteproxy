#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Command parsing, private-state startup, and foreground service lifecycle.

Both the console script and python -m fteproxy call main(). Exit statuses are
0 for success/clean shutdown, 1 for runtime failure, and 2 for usage errors.
Command output goes to stdout; progress and CLI logging go to stderr.
Parser diagnostics and the package logger redact recognized capability forms.
Run fteproxy help COMMAND for option syntax.
"""

import argparse
import ipaddress
import logging
import os
import re
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
DEFAULT_FORMAT = 'http'
DEFAULT_MODE = 'hybrid'

SUBCOMMANDS = ('server', 'client', 'keygen', 'formats', 'defs-check',
               'version', 'help')

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
    """Print the version notice without argparse reflowing its line breaks."""

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


# Once an argv value looks like a populated connection URI, discard the rest
# of the argparse diagnostic too. An argv element may legally contain a space
# or newline; redacting only up to that character would expose its suffix.
# Requiring one non-space character after ``//`` preserves instructional errors
# such as "must start with fte://".
_URI_ARGUMENT = re.compile(r'fte://(?=\S)\S+.*', re.IGNORECASE | re.DOTALL)


class _ArgumentParser(argparse.ArgumentParser):
    """An exact, capability-safe argument parser.

    Long-option abbreviations make scripts ambiguous as the CLI grows. More
    importantly, argparse normally repeats an unrecognised positional value in
    its error, which can copy a connection capability from argv into logs.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('allow_abbrev', False)
        super().__init__(*args, **kwargs)

    def error(self, message):
        message = _URI_ARGUMENT.sub('<redacted connection string>', message)
        super().error(message)


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

def configure_logging(quiet=False, verbose=False):
    """Configure stderr logging at INFO, ERROR (-q), or DEBUG (-v).

    The package's pattern-based redaction filter remains installed.
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


def _positive_integer(value):
    """An argparse type for resource limits, which may never be disabled."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError('must be a positive integer')
    if parsed < 1:
        raise argparse.ArgumentTypeError('must be a positive integer')
    return parsed


def _dated_release(value):
    """A definitions release that is safe to put in the wire handshake."""
    if re.fullmatch(r'[0-9]{8}', value) is None:
        raise argparse.ArgumentTypeError('must be an 8-digit YYYYMMDD release')
    return value


def _catalog_release(value):
    """A bounded definitions-catalog identifier, never a path."""
    try:
        return fteproxy.defs.validate_release_id(value)
    except fteproxy.defs.DefinitionsError as e:
        raise argparse.ArgumentTypeError(str(e))


def build_parser():
    parser = _ArgumentParser(
        prog='fteproxy',
        add_help=False,
        description='A format-transforming-encryption tunnel.',
        epilog='Run "fteproxy help COMMAND" for help with a command.')
    # Keep conventional aliases working while presenting actions as commands.
    parser.add_argument('-h', '--help', action='help', help=argparse.SUPPRESS)
    parser.add_argument('--version', action=_PrintVersion,
                        help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(
        dest='command', metavar='COMMAND', title='commands')

    server = subparsers.add_parser(
        'server', help='Accept tunnelled connections and dial where they ask.')
    server.set_defaults(_parser=server)
    server.add_argument('--listen', metavar='[HOST]:PORT', default=DEFAULT_LISTEN,
                        help='Address to listen on. ":PORT" means every '
                             'interface; IPv6 literals go in brackets.')
    server.add_argument('--allow', metavar='RULE', action='append', default=[],
                        help='A destination clients may reach: "any", '
                             'HOST[:PORT], CIDR[:PORT] or *.example.com[:PORT]. '
                             'Repeatable; supplied rules replace the default. '
                             'Only globally routable unicast destinations are '
                             'allowed by default; only an explicit IP/CIDR '
                             'rule opts a non-global address in.')
    server.add_argument('--advertise', metavar='HOST[:PORT]', default=None,
                        help='Reachable address to put in connection.txt. '
                             'Without it, keep this identity\'s existing '
                             'endpoint; otherwise use the concrete listen host '
                             'or loopback for a wildcard listener.')
    server.add_argument('--defs', metavar='RELEASE', type=_dated_release,
                        default=fteproxy.conf.getValue('fteproxy.defs.release'),
                        help='Definitions release to serve, as YYYYMMDD.')
    server.add_argument(
        '--print-connection', action='store_true',
        help='Print the connection capability to stdout after storing it. '
             'By default only its file path is reported.')
    server.add_argument(
        '--max-pending', metavar='N', type=_positive_integer,
        default=fteproxy.conf.getValue('runtime.fteproxy.relay.max_pending'),
        help='Maximum concurrent handshake/OPEN setups (default: %(default)s).')
    server.add_argument(
        '--max-pending-per-source', metavar='N', type=_positive_integer,
        default=fteproxy.conf.getValue(
            'runtime.fteproxy.relay.max_pending_per_source'),
        help='Maximum concurrent setups per source IP (default: %(default)s).')
    server.add_argument(
        '--max-active', metavar='N', type=_positive_integer,
        default=fteproxy.conf.getValue('runtime.fteproxy.relay.max_active'),
        help='Maximum established sessions (default: %(default)s).')
    server.add_argument(
        '--max-active-per-source', metavar='N', type=_positive_integer,
        default=fteproxy.conf.getValue(
            'runtime.fteproxy.relay.max_active_per_source'),
        help='Maximum established sessions per source IP '
             '(default: %(default)s).')
    _state_dir_flag(server)
    _verbosity(server)

    client = subparsers.add_parser(
        'client', help='Listen locally and tunnel to an fteproxy server.')
    client.set_defaults(_parser=client)
    client.add_argument('uri', nargs='?', metavar='URI', default=None,
                        help='fte://SERVER-ID@HOST:PORT. Falls back to '
                             '$FTEPROXY_URI, then connection.txt in the state '
                             'directory.')
    source = client.add_mutually_exclusive_group()
    source.add_argument(
        '--connection-file', metavar='FILE', default=None,
        help='Read the connection string from FILE instead of exposing it in '
             'process arguments.')
    source.add_argument(
        '--connection-stdin', action='store_true',
        help='Read the connection string from standard input instead of '
             'exposing it in process arguments.')
    client.add_argument('-D', '--socks-listen', metavar='[BIND:]PORT',
                        action='append',
                        dest='socks', default=[],
                        help='SOCKS5 listener. The default when neither -D nor '
                             '-L is given is ' + DEFAULT_SOCKS + '.')
    client.add_argument(
        '--expose-listeners', action='store_true',
        help='Allow SOCKS5 and forwarding listeners outside loopback. Anyone '
             'who can reach them can use the tunnel.')
    client.add_argument(
        '--max-pending', metavar='N', type=_positive_integer,
        default=fteproxy.conf.getValue(
            'runtime.fteproxy.relay.client_max_pending'),
        help='Maximum concurrent local connection setups '
             '(default: %(default)s).')
    client.add_argument(
        '--max-pending-per-source', metavar='N', type=_positive_integer,
        default=fteproxy.conf.getValue(
            'runtime.fteproxy.relay.client_max_pending_per_source'),
        help='Maximum concurrent local setups per source IP '
             '(default: %(default)s).')
    client.add_argument('-L', '--forward',
                        metavar='[BIND:]PORT:HOST:PORT', action='append',
                        dest='forwards', default=[],
                        help='Forward a local port to one destination through '
                             'the tunnel. Repeatable.')
    client.add_argument('--format', metavar='NAME', default=None,
                        help='Base format name; see "fteproxy formats" '
                             '(default: the URI\'s hint, else the format '
                             'whose protocol runs on the server\'s port, '
                             'else %s).' % DEFAULT_FORMAT)
    client.add_argument('--mode', choices=['hybrid', 'format'], default=None,
                        help='Record framing: "hybrid" uses FTE headers and '
                             'encrypted bodies (HTTP adds chunk framing); '
                             '"format" encodes payloads into covertexts at '
                             'lower throughput. Default: URI hint, then format '
                             'mode hint, then %s.' % DEFAULT_MODE)
    client.add_argument('--no-check', action='store_true',
                        help='Skip the startup check, which otherwise opens '
                             'one short session so a bad connection string '
                             'fails now instead of on first use.')
    _state_dir_flag(client)
    _verbosity(client)

    keygen = subparsers.add_parser(
        'keygen', help='Create server.key if absent and print the connection '
                       'string.')
    keygen.set_defaults(_parser=keygen)
    keygen.add_argument('--advertise', metavar='HOST[:PORT]', default=None,
                        help='The address to put in the connection string. '
                             'Without it, keep this identity\'s existing '
                             'endpoint or default to 127.0.0.1:8080.')
    keygen.add_argument('--defs', metavar='RELEASE', type=_dated_release,
                        default=fteproxy.conf.getValue('fteproxy.defs.release'),
                        help='Definitions release to put in the connection '
                             'string, as YYYYMMDD.')
    _state_dir_flag(keygen)
    _verbosity(keygen)

    formats = subparsers.add_parser(
        'formats', help='List the formats in a definitions file.')
    formats.set_defaults(_parser=formats)
    formats.add_argument('--defs', metavar='RELEASE', type=_catalog_release,
                         default=fteproxy.conf.getValue('fteproxy.defs.release'),
                         help='Definitions release or legacy alias to list.')
    _verbosity(formats)

    defs_check = subparsers.add_parser(
        'defs-check', help='Validate every format in a definitions release: '
                           'build the cipher, check the capacity floor, '
                           'round-trip the record layer, and confirm every '
                           'format-mode covertext matches its regex.')
    defs_check.set_defaults(_parser=defs_check)
    defs_check.add_argument('--defs', metavar='RELEASE', type=_catalog_release,
                            default=fteproxy.conf.getValue(
                                'fteproxy.defs.release'),
                            help='Definitions release or legacy alias to '
                                 'validate.')
    _verbosity(defs_check)

    version = subparsers.add_parser(
        'version', help='Print the version and licence, then quit.',
        description='Print the version and licence, then quit.')
    version.set_defaults(_parser=version)

    help_parser = subparsers.add_parser(
        'help', help='Show general help or help for a command.')
    help_parser.add_argument(
        'topic', nargs='?', choices=SUBCOMMANDS, metavar='COMMAND',
        help='Command to describe; omit to show general help.')
    help_parser.set_defaults(
        _parser=help_parser,
        _help_parsers={None: parser, **subparsers.choices})

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
    """Select ``release`` as the process default and load it now.

    Loading validates every format in the file, so a release that cannot carry
    a handshake fails here rather than as a client that hangs. Definitions are
    cached by release, so changing this default needs no private cache reset.
    """
    fteproxy.conf.setValue('fteproxy.defs.release', release)
    try:
        return fteproxy.defs.load_definitions(release)
    except (OSError, fteproxy.defs.DefinitionsError) as e:
        raise StartupError('cannot load definitions release %s: %s'
                           % (release, e))


def check_format(base):
    """Build both directions of ``base`` so an unusable format fails now.

    Every length each direction may emit, not just the one the handshake uses:
    a variable-length format that cannot compile at one of its shorter lengths
    would otherwise fail mid-connection instead of here. The DFAs land in
    :func:`fteproxy._regex_format`'s cache, so the first connection does not pay
    for them either -- which means asking for the same lengths a connection
    will: the *message* length for a length-prefix format, whose framing prefix
    is not part of the pattern.
    """
    try:
        request, response = fteproxy.defs.getRegex(base + '-request'), \
            fteproxy.defs.getRegex(base + '-response')
    except fteproxy.defs.InvalidRegexName:
        raise StartupError(
            'unknown format %r; "fteproxy formats" lists the base names' % base)
    for name, pattern in ((base + '-request', request),
                          (base + '-response', response)):
        framing = fteproxy.defs.get_framing(name)
        for length in fteproxy.defs.get_allowed_lengths(name):
            try:
                fteproxy._regex_format(
                    pattern, fteproxy._message_length(framing, length))
            except Exception as e:
                raise StartupError('format %s is unusable at length %d: %s'
                                   % (name, length, e))


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

    # The host is interpolated into a URI authority. Reject every character
    # that could move text into userinfo, a path, a query or a fragment, plus
    # the legacy sentinel which is never a usable remote address.
    if (host == fteproxy.config.HOST_PLACEHOLDER
            or any(char in '@/\\?#<>' or char.isspace()
                   or ord(char) < 0x20 or 0x7f <= ord(char) <= 0x9f
                   for char in host)):
        raise UsageError('--advertise needs a literal IP address or safe host '
                         'name, not URI delimiters or <server-ip>')
    if text.startswith('['):
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise UsageError('--advertise brackets are only for an IPv6 '
                             'literal')

    # Prove that rendering and parsing the invitation preserves the exact
    # address. This catches authority edge cases without duplicating the URI
    # parser's rules here.
    try:
        candidate = fteproxy.config.ConnectionString(
            b'\x00' * fteproxy.handshake.KEY_BYTES, host, port)
        round_trip = fteproxy.config.ConnectionString.parse(candidate.format())
    except fteproxy.config.ConfigError:
        raise UsageError('--advertise is not safe in a connection string')
    if round_trip.address != (host, port):
        raise UsageError('--advertise does not round-trip as the same address')
    return host, port


def default_advertise_host(listen_host):
    """A valid same-host address for a listener with no ``--advertise``."""
    if not listen_host:
        return '127.0.0.1'
    try:
        address = ipaddress.ip_address(listen_host)
    except ValueError:
        return listen_host
    if address.is_unspecified:
        return '::1' if address.version == 6 else '127.0.0.1'
    return listen_host


def _is_wildcard_listener(host):
    """Whether ``host`` accepts interfaces but names no remote endpoint."""
    if not host:
        return True
    try:
        return ipaddress.ip_address(host).is_unspecified
    except ValueError:
        return False


def _previous_advertise(directory, public):
    """Return the prior endpoint for this identity, if one is usable.

    A listener cannot reveal the public DNS name or NAT mapping that clients
    use.  The existing connection file records an endpoint the operator already
    chose. Reusing only that endpoint, and only while its server-id still
    matches, keeps a routine restart or keygen invocation from replacing a
    working remote invitation with a valid-looking local one.
    """
    try:
        text = fteproxy.config.read_connection_string(directory)
        if not text:
            return None
        previous = fteproxy.config.ConnectionString.parse(text)
    except fteproxy.config.ConfigError as e:
        fteproxy.warn('cannot reuse the endpoint in %s: %s'
                      % (fteproxy.config.connection_path(directory), e))
        return None
    if (previous.server_id != public
            or previous.host == fteproxy.config.HOST_PLACEHOLDER):
        return None
    return previous.address


# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #

def do_keygen(args):
    host, port = '127.0.0.1', fteproxy.config.DEFAULT_PORT
    if args.advertise:
        host, port = parse_advertise(args.advertise, port)
    select_defs(args.defs)

    directory = resolve_state_dir(args)
    private, public, created = fteproxy.config.ensure_server_key(directory)
    del private

    reused_advertise = False
    if not args.advertise:
        previous = _previous_advertise(directory, public)
        if previous is not None:
            host, port = previous
            reused_advertise = True

    uri = fteproxy.config.ConnectionString(public, host, port,
                                           defs=str(args.defs))
    path = fteproxy.config.write_connection_string(directory, uri)

    _report(args, '%s %s'
            % ('wrote' if created else 'kept',
               fteproxy.config.server_key_path(directory)))
    _report(args, 'connection string also written to %s' % path)
    if reused_advertise:
        _report(args, 'kept the previously advertised remote endpoint')
    print(uri.format())
    return EXIT_OK


def _span(low, high):
    """``512`` for one value, ``200-700`` for a range."""
    return str(low) if low == high else '%d-%d' % (low, high)


def _hybrid_header_cell(directions, definitions):
    """Render header wire lengths: one value, request/response, or '-' if unusable."""
    cells = []
    for direction in ('request', 'response'):
        name = directions.get(direction)
        if name is None:
            continue
        try:
            length = fteproxy.hybrid_header_length(definitions[name])
        except Exception:
            length = None
        if length is None:
            return '-'
        cells.append(str(length))
    if not cells:
        return '-'
    if len(set(cells)) == 1:
        return cells[0]
    return '/'.join(cells)


def do_formats(args):
    """List base names, direction metadata, wire lengths, and cipher capacities.

    Capacity includes the seal/type space used by session records. Variable formats
    show min/max ranges; hdr shows each direction's hybrid-header wire length.
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

    default = fteproxy.defs.default_base(definitions) or DEFAULT_FORMAT

    _ROLE_ABBR = {'request': 'req', 'response': 'resp', 'line': 'line'}

    rows = []
    descriptions = {}
    defaults = {}
    for base in sorted(bases):
        row = [base]
        # port, mode_hint, role and description are format-level; take them from
        # the request entry (where a connection's port lives), else the response.
        primary = bases[base].get('request') or bases[base].get('response')
        primary_spec = definitions[primary]
        roles = []
        for direction in ('request', 'response'):
            name = bases[base].get(direction)
            if name is not None:
                roles.append(_ROLE_ABBR.get(
                    fteproxy.defs.spec_role(name, definitions[name]),
                    fteproxy.defs.spec_role(name, definitions[name])))
        # Preserve order, drop duplicates.
        role = '/'.join(dict.fromkeys(roles)) or '-'
        ports = fteproxy.defs.spec_port(primary_spec)
        port = ','.join(str(p) for p in ports) if ports else '-'
        mode = fteproxy.defs.spec_mode_hint(primary_spec)
        row += [role, port, mode, _hybrid_header_cell(bases[base], definitions)]
        for direction in ('request', 'response'):
            name = bases[base].get(direction)
            if name is None:
                row += ['-', '-']
                continue
            spec = definitions[name]
            lengths = fteproxy.defs.spec_allowed_lengths(spec)
            shortest, longest = lengths[0], lengths[-1]
            try:
                capacities = [fteproxy._spec_cipher(
                    spec, length, key).max_plaintext_bytes
                    for length in (shortest, longest)]
            except Exception:
                row += [_span(shortest, longest), 'unusable']
                continue
            row += [_span(shortest, longest),
                    _span(min(capacities), max(capacities))]
        rows.append(row)
        descriptions[base] = fteproxy.defs.spec_description(primary_spec)
        defaults[base] = (base == default)

    header = ['name', 'role', 'port', 'mode', 'hdr',
              'req len', 'req cap', 'resp len', 'resp cap']
    left = {0, 1, 2, 3}  # name/role/port/mode left-justified; numbers right
    widths = [max(len(r[i]) for r in [header] + rows) for i in range(len(header))]
    print('definitions release %s' % args.defs)
    print('role, port, mode, and wire length / cipher capacity (bytes) '
          'per direction')
    print('a length range means the format varies its covertext length per '
          'record in format mode')
    print('hdr is the covertext length a hybrid-mode header goes in '
          '(request/response when they differ)')
    print()

    def _emit(row, trailer):
        cells = [cell.ljust(widths[i]) if i in left else cell.rjust(widths[i])
                 for i, cell in enumerate(row)]
        print(('  '.join(cells) + trailer).rstrip())

    _emit(header, '')
    for row in rows:
        base = row[0]
        trailer = ''
        if defaults[base]:
            trailer += '  (default)'
        if descriptions[base]:
            trailer += '  ' + descriptions[base]
        _emit(row, trailer)
    return EXIT_OK


def do_defs_check(args):
    """Validate a release, print capacity/framing summaries, and return 0 or 1."""
    import fteproxy.defs.validate as validate
    try:
        summary = validate.validate_release(args.defs)
    except FileNotFoundError as e:
        fteproxy.logger.error('cannot load definitions release %s: %s'
                              % (args.defs, e))
        return EXIT_FAILURE
    except validate.FormatValidationError as e:
        print('FAIL: definitions release %s' % args.defs)
        print(str(e))
        return EXIT_FAILURE

    print('OK: definitions release %s (%d format%s)'
          % (args.defs, len(summary), '' if len(summary) == 1 else 's'))
    if summary:
        # The summary reports the length the handshake seals at; a
        # variable-length format also emits shorter covertexts, so show the
        # whole span it may emit and mark that the capacity is the largest one.
        # Read the file directly, as validate_release does, rather than pointing
        # the process-wide loader at a release the caller only asked to check.
        import json
        with open(fteproxy.defs._release_path(args.defs)) as handle:
            definitions = json.load(handle)
        name_w = max(len(name) for name, _l, _c, _m in summary)
        spans = {}
        headers = {}
        for name, length, _capacity, _mode in summary:
            spec = definitions.get(name, {'length': length})
            lengths = fteproxy.defs.spec_allowed_lengths(spec)
            spans[name] = _span(lengths[0], lengths[-1])
            # Validation has already refused anything with no such length, so
            # this is a number for every format that got here.
            try:
                headers[name] = str(fteproxy.hybrid_header_length(spec))
            except Exception:
                headers[name] = '-'
        span_w = max(len(span) for span in spans.values())
        header_w = max(len(value) for value in headers.values())
        for name, _length, capacity, mode_hint in summary:
            print('  %s  length %s  capacity %5d  hybrid header %s  %s'
                  % (name.ljust(name_w), spans[name].rjust(span_w),
                     capacity, headers[name].rjust(header_w), mode_hint))
        if any('-' in span for span in spans.values()):
            print('a length range varies per record in format mode; the '
                  'capacity shown is the one at the top of the range')
        print('the two handshake records seal at the top of the range; a '
              'hybrid-mode header seals at the shortest length that holds one')
    return EXIT_OK


def do_server(args):
    # Parse every operator-controlled value before creating or modifying state.
    try:
        host, port = fteproxy.config.split_host_port(args.listen)
    except ValueError as e:
        raise UsageError('--listen %s' % e)

    try:
        rules = fteproxy.stream.AllowRules(args.allow)
    except fteproxy.stream.InvalidRule as e:
        raise UsageError(str(e))

    if args.advertise:
        advertise_host, advertise_port = parse_advertise(args.advertise, port)
    else:
        local_host = default_advertise_host(host)
        advertise_host, advertise_port = parse_advertise(
            _render_address(local_host, port), port)

    select_defs(args.defs)
    directory = resolve_state_dir(args, create=False)
    fteproxy.config.validate_state_dir(directory, missing_ok=True)
    private = fteproxy.config.load_server_key(directory)
    if private is None:
        private, public = fteproxy.generate_server_key()
        created = True
    else:
        public = fteproxy.server_id(private)
        created = False

    listener = fteproxy.relay.ServerListener(
        host, port, private, rules=rules, max_pending=args.max_pending,
        max_pending_per_source=args.max_pending_per_source,
        max_active=args.max_active,
        max_active_per_source=args.max_active_per_source)
    try:
        listener.bind()
    except OSError as e:
        listener.stop()
        raise StartupError('cannot listen on %s: %s' % (args.listen, e))
    except BaseException:
        listener.stop()
        raise

    # Keep the socket claimed while persisting its identity and invitation. A
    # first-run bind failure therefore leaves no identity behind, and a failed
    # restart cannot overwrite a previously working invitation.
    try:
        fteproxy.config.ensure_state_dir(directory)
        winning_private, public, created = \
            fteproxy.config.claim_server_key(directory, private)
        if winning_private != private:
            raise StartupError(
                'server identity was initialized concurrently; retry so the '
                'listener uses the stored identity')
        reused_advertise = False
        if not args.advertise:
            previous = _previous_advertise(directory, public)
            if previous is not None:
                advertise_host, advertise_port = previous
                reused_advertise = True
        uri = fteproxy.config.ConnectionString(
            public, advertise_host, advertise_port, defs=str(args.defs))
        connection_file = fteproxy.config.write_connection_string(directory,
                                                                    uri)
    except BaseException:
        listener.stop()
        raise

    try:
        bound_host, bound_port = listener.address
        _report(args, 'listening on %s'
                % _render_address(bound_host, bound_port))
        _report(args, 'key: %s%s'
                % (fteproxy.config.server_key_path(directory),
                   ' (created)' if created else ''))
        _report(args, 'allowing: %s' % rules.describe())
        _report(args, 'connection string written to %s' % connection_file)
        if reused_advertise:
            _report(args, 'kept the previously advertised remote endpoint')
        elif not args.advertise and _is_wildcard_listener(host):
            fteproxy.warn(
                'connection.txt is local-only; use --advertise HOST[:PORT] '
                'before sharing it with another machine')
        if args.print_connection:
            print(uri.format())
            sys.stdout.flush()
        return serve_forever([listener])
    finally:
        _stop_listeners([listener])


def mode_hint_for(base):
    """The record-layer mode a base format was designed for, or None.

    Read from the request side's ``mode_hint`` in the loaded definitions
    release. None when the format is not in the release, so the caller falls
    through to the built-in default; ``check_format`` has already refused an
    unknown base by the time this runs.
    """
    try:
        return fteproxy.defs.get_mode_hint(base + fteproxy.defs.REQUEST_SUFFIX)
    except (fteproxy.defs.InvalidRegexName, KeyError):
        return None


def _is_loopback_bind(host):
    """Whether a local listener host is a literal loopback address."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def do_client(args):
    # Local listener syntax and exposure policy are independent of the secret
    # connection source, so reject them before reading a file or stdin.
    try:
        socks_specs = [fteproxy.config.split_socks_spec(spec)
                       for spec in args.socks]
        forwards = [fteproxy.config.split_forward_spec(spec)
                    for spec in args.forwards]
    except ValueError as e:
        raise UsageError(str(e))
    if not socks_specs and not forwards:
        socks_specs = [fteproxy.config.split_socks_spec(DEFAULT_SOCKS)]

    exposed = ([('SOCKS5', bind, port) for bind, port in socks_specs
                if not _is_loopback_bind(bind)]
               + [('forward', bind, port) for (bind, port), _ in forwards
                  if not _is_loopback_bind(bind)])
    if exposed and not args.expose_listeners:
        kind, bind, port = exposed[0]
        raise UsageError(
            '%s listener %s is outside loopback; use --expose-listeners to '
            'make it reachable from other machines'
            % (kind, _render_address(bind, port)))
    for kind, bind, port in exposed:
        fteproxy.warn(
            '%s listener on %s is exposed; anyone who can reach it can use '
            'the tunnel' % (kind, _render_address(bind, port)))

    explicit_sources = sum((args.uri is not None,
                            args.connection_file is not None,
                            bool(args.connection_stdin)))
    if explicit_sources > 1:
        raise UsageError('choose only one of URI, --connection-file, or '
                         '--connection-stdin')

    directory = resolve_state_dir(args, create=False)
    if not explicit_sources and not os.environ.get(fteproxy.config.ENV_URI):
        # An implicit capability is trusted because it lives in private state.
        # Refuse a directory that would let another local user read or replace
        # it; an explicit file remains usable independently of this directory.
        fteproxy.config.validate_state_dir(directory, missing_ok=True)
    try:
        uri, source = fteproxy.config.resolve_client_uri(
            args.uri, directory, connection_file=args.connection_file,
            input_stream=sys.stdin if args.connection_stdin else None)
    except fteproxy.config.ConfigError as e:
        raise UsageError(str(e))
    if uri is None:
        raise UsageError(
            'no connection string. Pass one with --connection-file, '
            '--connection-stdin or URI; set %s; or run the server once so it '
            'writes %s.'
            % (fteproxy.config.ENV_URI,
               fteproxy.config.connection_path(directory)))
    fteproxy.debug('connection string from %s' % source)

    # The definitions release is the server operator's to choose: the client
    # takes it from the URI's hint, since a mismatch is refused at the far end.
    defs = uri.defs or fteproxy.conf.getValue('fteproxy.defs.release')
    select_defs(str(defs))

    # Flags beat the URI's hints, which beat the port default, which beats the
    # built-in one. The port default is what makes a server parked on 21 speak
    # FTP-shaped covertexts without anyone saying so.
    from_port = fteproxy.config.format_for_port(uri.port)
    base = args.format or uri.format_name or from_port or DEFAULT_FORMAT
    check_format(base)
    # Mode precedence: CLI flag, URI hint, format hint, built-in default.
    mode = args.mode or uri.mode or mode_hint_for(base) or DEFAULT_MODE
    if args.format and from_port and args.format != from_port:
        fteproxy.warn('format %s does not match port %d, where %s is what an '
                      'observer expects' % (args.format, uri.port, from_port))

    # One allocator is shared by every -D/-L listener in this client process;
    # otherwise each additional listening port would multiply the advertised
    # global setup bound.
    setup_admission = fteproxy.relay._SetupAdmission(
        args.max_pending, args.max_pending_per_source)
    common = dict(server_address=uri.address, server_id=uri.server_id,
                  format=base, mode=mode, defs=str(defs),
                  max_pending=args.max_pending,
                  max_pending_per_source=args.max_pending_per_source,
                  setup_admission=setup_admission)

    listeners = []
    for bind, port in socks_specs:
        listeners.append(fteproxy.relay.SocksListener(bind, port, **common))
    for (bind, port), destination in forwards:
        listeners.append(fteproxy.relay.ForwardListener(
            bind, port, destination=destination, **common))

    bound = []
    for listener in listeners:
        try:
            listener.bind()
        except BaseException as e:
            for started in bound:
                started.stop()
            if isinstance(e, OSError):
                raise StartupError('cannot listen on %s: %s'
                                   % (_render_address(*listener.address), e))
            raise
        bound.append(listener)

    try:
        if not args.no_check:
            checked = run_startup_check(args, listeners[0], uri)
            if not checked:
                return EXIT_FAILURE

        for listener, spec in zip(
                listeners,
                [('SOCKS5', None) for _ in socks_specs]
                + [('forward', destination) for _, destination in forwards]):
            kind, destination = spec
            where = _render_address(*listener.address)
            if destination is None:
                _report(args, 'SOCKS5 on %s' % where)
            else:
                _report(args, 'forwarding %s to %s through the tunnel'
                        % (where, _render_address(*destination)))
        return serve_forever(listeners)
    finally:
        _stop_listeners(bound)


def run_startup_check(args, listener, uri):
    """Report a handshake-only check on stderr and return whether it succeeded.

    A failure can take the handshake timeout. No destination is opened.
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

def _stop_listeners(listeners):
    """Best-effort cleanup that never masks the error which triggered it."""
    for listener in listeners:
        try:
            listener.stop()
        except Exception:
            pass


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
    started = []
    status = EXIT_OK
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                previous[signum] = signal.signal(signum, _stop)
            except ValueError:
                # Not the main thread (an embedding program calling main()).
                pass

        # Listener sockets are already bound. Keep startup inside the cleanup
        # region so a later listener whose thread cannot start does not strand
        # the earlier sockets or our temporary signal handlers.
        try:
            for listener in listeners:
                listener.daemon = True
                listener.start()
                started.append(listener)
        except Exception as e:
            fteproxy.logger.error('could not start listener: %s' % e)
            status = EXIT_FAILURE

        while status == EXIT_OK and started and not stopping.is_set():
            failures = [
                (listener, getattr(listener, 'terminal_error', None))
                for listener in started
                if getattr(listener, 'terminal_error', None) is not None
            ]
            if failures:
                for _listener, error in failures:
                    fteproxy.logger.error('listener failed: %s' % error)
                status = EXIT_FAILURE
                break

            # A listener which simply falls out of run() is also a failed
            # service, even if an unexpected exception kept it from recording
            # a more useful terminal_error.
            if any(not listener.is_alive() for listener in started):
                fteproxy.logger.error('listener stopped unexpectedly')
                status = EXIT_FAILURE
                break
            stopping.wait(0.5)
    finally:
        try:
            _stop_listeners(listeners)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    return status


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

_COMMANDS = {
    'server': do_server,
    'client': do_client,
    'keygen': do_keygen,
    'formats': do_formats,
    'defs-check': do_defs_check,
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

    if args.command == 'help':
        args._help_parsers[args.topic].print_help()
        return EXIT_OK

    if args.command == 'version':
        print(_LICENSE_BANNER)
        return EXIT_OK

    configure_logging(quiet=args.quiet, verbose=args.verbose)

    try:
        return _COMMANDS[args.command](args)
    except UsageError as e:
        args._parser.error(str(e))  # exits 2 with the selected command's usage
    except (StartupError, fteproxy.config.ConfigError) as e:
        fteproxy.logger.error(str(e))
        return EXIT_FAILURE
    except KeyboardInterrupt:
        return EXIT_OK
