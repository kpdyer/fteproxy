#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The connection string and the state directory.

A 1.0 client needs one argument, and this is what it holds::

    fte://<server-id>@<host>:<port>[?format=<base>&mode=<hybrid|format>&defs=<YYYYMMDD>]

``server-id`` is the server's X25519 public key in base64url without padding,
43 characters. The query parameters are hints the operator recommends; a flag
on the command line beats them, and an unknown parameter is ignored so a later
version can add one without breaking today's clients.

Treat the whole string like a Tor bridge line: whoever holds it can connect,
and its secrecy is what stops an active prober confirming the server. It does
not let the holder impersonate the server or read another client's traffic --
see :mod:`fteproxy.handshake`.

The state directory is where a server keeps the private half and the string it
hands out. Resolution order: ``--state-dir``, ``FTEPROXY_STATE_DIR``,
``$XDG_STATE_HOME/fteproxy``, ``~/.local/state/fteproxy``.
"""

import base64
import os
import stat
import urllib.parse

import fteproxy
import fteproxy.handshake


SCHEME = 'fte'
DEFAULT_PORT = 8080

SERVER_KEY_FILE = 'server.key'
CONNECTION_FILE = 'connection.txt'

#: What a connection string carries in place of a host the server cannot know.
#: A server does not learn its own public address by starting up, so it writes
#: this and the operator substitutes the address clients should dial, or passes
#: ``--advertise``.
HOST_PLACEHOLDER = '<server-ip>'

#: Directory mode 0700 and file mode 0600: the private key and the connection
#: string are both secrets, and a state directory readable by other local users
#: hands them over.
DIR_MODE = 0o700
FILE_MODE = 0o600

ENV_STATE_DIR = 'FTEPROXY_STATE_DIR'
ENV_URI = 'FTEPROXY_URI'


class ConfigError(Exception):
    """A connection string or a state directory that cannot be used."""


# --------------------------------------------------------------------------- #
# Server identity encoding
# --------------------------------------------------------------------------- #

def encode_server_id(public_bytes):
    """32 bytes -> the 43-character base64url server-id."""
    return base64.urlsafe_b64encode(public_bytes).rstrip(b'=').decode('ascii')


def decode_server_id(text):
    """The 43-character base64url server-id -> 32 bytes."""
    padded = text + '=' * (-len(text) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode('ascii'))
    except (ValueError, UnicodeEncodeError):
        raise ConfigError('server-id is not valid base64url')
    if len(raw) != fteproxy.handshake.KEY_BYTES:
        raise ConfigError('server-id must decode to %d bytes, got %d'
                          % (fteproxy.handshake.KEY_BYTES, len(raw)))
    return raw


# --------------------------------------------------------------------------- #
# The connection string
# --------------------------------------------------------------------------- #

class ConnectionString:
    """One parsed ``fte://`` URI.

    ``server_id`` is the 32-byte public key; ``format_name``, ``mode`` and
    ``defs`` are the operator's hints and are None when the string carries
    none.
    """

    __slots__ = ('server_id', 'host', 'port', 'format_name', 'mode', 'defs')

    def __init__(self, server_id, host, port=DEFAULT_PORT, format_name=None,
                 mode=None, defs=None):
        if len(server_id) != fteproxy.handshake.KEY_BYTES:
            raise ConfigError('server-id must be %d bytes'
                              % fteproxy.handshake.KEY_BYTES)
        if not host:
            raise ConfigError('a connection string needs a host')
        if not 0 < port <= 0xFFFF:
            raise ConfigError('port %r is out of range' % (port,))
        if mode is not None and mode not in fteproxy.handshake.MODES:
            raise ConfigError('mode must be one of %s'
                              % ', '.join(fteproxy.handshake.MODES))
        self.server_id = bytes(server_id)
        self.host = host
        self.port = port
        self.format_name = format_name
        self.mode = mode
        self.defs = defs

    # -- parsing ----------------------------------------------------------- #

    @classmethod
    def parse(cls, text):
        """Parse an ``fte://`` URI, raising :class:`ConfigError`.

        No error message ever quotes the string: an unparseable one is still a
        secret, and error output is the easiest place for it to leak.
        """
        text = text.strip()
        if not text:
            raise ConfigError('empty connection string')
        parsed = urllib.parse.urlsplit(text)
        if parsed.scheme != SCHEME:
            raise ConfigError('connection string must start with %s://'
                              % SCHEME)
        if parsed.path not in ('', '/') or parsed.fragment:
            raise ConfigError('a connection string carries no path or fragment')
        if '@' not in parsed.netloc:
            raise ConfigError('connection string has no server-id before @')

        raw_id, _, authority = parsed.netloc.rpartition('@')
        if ':' in raw_id:
            raise ConfigError('a connection string carries no password')
        server_id = decode_server_id(raw_id)

        try:
            host, port = split_host_port(authority, default_port=DEFAULT_PORT)
        except ValueError as e:
            raise ConfigError(str(e))
        if not host:
            raise ConfigError('a connection string needs a host')

        hints = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        mode = hints.get('mode', [None])[0]
        if mode is not None and mode not in fteproxy.handshake.MODES:
            raise ConfigError('mode hint must be one of %s'
                              % ', '.join(fteproxy.handshake.MODES))
        defs = hints.get('defs', [None])[0]
        if defs is not None and not defs.isdigit():
            raise ConfigError('defs hint must be a YYYYMMDD release')
        return cls(server_id=server_id, host=host, port=port,
                   format_name=hints.get('format', [None])[0], mode=mode,
                   defs=defs)

    # -- rendering --------------------------------------------------------- #

    def format(self):
        """The URI this object round-trips from."""
        host = '[%s]' % self.host if _is_ipv6_literal(self.host) else self.host
        query = [('format', self.format_name), ('mode', self.mode),
                 ('defs', self.defs)]
        suffix = urllib.parse.urlencode(
            [(key, value) for key, value in query if value is not None])
        return '%s://%s@%s:%d%s' % (SCHEME, encode_server_id(self.server_id),
                                    host, self.port,
                                    '?' + suffix if suffix else '')

    def redacted(self):
        """The string with the server-id removed, for logs and messages."""
        host = '[%s]' % self.host if _is_ipv6_literal(self.host) else self.host
        return '%s://…@%s:%d' % (SCHEME, host, self.port)

    @property
    def address(self):
        return (self.host, self.port)

    def with_host(self, host, port=None):
        """A copy pointed at a different address.

        Used for the placeholder a server writes before it knows what clients
        should dial.
        """
        return ConnectionString(self.server_id, host,
                                self.port if port is None else port,
                                self.format_name, self.mode, self.defs)

    def __str__(self):
        # Never the URI: a ConnectionString can reach a log line or a
        # traceback, and format() is the deliberate way to render one.
        return self.redacted()

    def __repr__(self):
        return '<ConnectionString %s>' % self.redacted()

    def __eq__(self, other):
        if not isinstance(other, ConnectionString):
            return NotImplemented
        return all(getattr(self, name) == getattr(other, name)
                   for name in self.__slots__)


def format_for_port(port, definitions=None):
    """The base format a server on ``port`` most likely wants, or ``None``.

    Every shipped format names the ports its protocol is normally seen on
    (schema v2's ``port`` list), so a client dialing a server parked on 21 can
    speak FTP-shaped covertexts without being told to. The first entry in file
    order that claims the port wins, and a release whose formats carry no port
    lists (the shape catalog) matches nothing, leaving the caller's own default
    in place.

    This is only a default: ``--format`` and the connection string's
    ``?format=`` hint both beat it.
    """
    import fteproxy.defs  # deferred: fteproxy.defs imports this module's package
    if definitions is None:
        definitions = fteproxy.defs.load_definitions()
    for name, spec in definitions.items():
        if port in fteproxy.defs.spec_port(spec):
            return fteproxy.defs.base_name(name)
    return None


def _is_ipv6_literal(host):
    return ':' in host


def split_host_port(text, default_port=None, allow_bare_port=False):
    """``host``, ``host:port``, ``:port``, ``[v6]`` or ``[v6]:port``.

    Returns ``(host, port)``; the host is ``''`` for ``:port``, which means
    every interface. IPv6 literals need brackets whenever a port follows,
    because ``::1:8080`` is a valid address on its own. Raises ``ValueError``.
    """
    text = text.strip()
    if not text:
        raise ValueError('empty address')
    if text.startswith('['):
        end = text.find(']')
        if end < 0:
            raise ValueError('unclosed [ in %r' % text)
        host = text[1:end]
        rest = text[end + 1:]
        if not rest:
            return host, _require_port(default_port, text)
        if not rest.startswith(':'):
            raise ValueError('expected :PORT after ] in %r' % text)
        return host, _parse_port(rest[1:], text)
    if text.count(':') == 1:
        host, _, port = text.partition(':')
        return host, _parse_port(port, text)
    if ':' in text:
        # Several colons and no brackets: a bare IPv6 literal.
        return text, _require_port(default_port, text)
    if allow_bare_port and text.isdigit():
        return '', _parse_port(text, text)
    return text, _require_port(default_port, text)


def _parse_port(text, whole):
    if not text.isdigit():
        raise ValueError('port %r in %r is not a number' % (text, whole))
    port = int(text)
    if not 0 < port <= 0xFFFF:
        raise ValueError('port %d in %r is out of range' % (port, whole))
    return port


def _require_port(default_port, whole):
    if default_port is None:
        raise ValueError('%r needs a port' % whole)
    return default_port


def split_forward_spec(text):
    """``[BIND:]PORT:HOST:PORT`` -> ``((bind, port), (host, port))``.

    ssh's ``-L`` spelling. Splitting happens outside brackets, so
    ``[::1]:2222:[2001:db8::1]:22`` means what it looks like.
    """
    parts = _split_outside_brackets(text)
    if len(parts) == 3:
        bind, local_port, host, port = '127.0.0.1', parts[0], parts[1], parts[2]
    elif len(parts) == 4:
        bind, local_port, host, port = parts
    else:
        raise ValueError('expected [BIND:]PORT:HOST:PORT, got %r' % text)
    return ((_strip_brackets(bind), _parse_port(local_port, text)),
            (_strip_brackets(host), _parse_port(port, text)))


def split_socks_spec(text):
    """``[BIND:]PORT`` -> ``(bind, port)``, defaulting the bind to loopback."""
    parts = _split_outside_brackets(text)
    if len(parts) == 1:
        return '127.0.0.1', _parse_port(parts[0], text)
    if len(parts) == 2:
        return _strip_brackets(parts[0]), _parse_port(parts[1], text)
    raise ValueError('expected [BIND:]PORT, got %r' % text)


def _split_outside_brackets(text):
    parts, current, depth = [], '', 0
    for char in text:
        if char == '[':
            depth += 1
        elif char == ']':
            depth -= 1
            if depth < 0:
                raise ValueError('unbalanced ] in %r' % text)
        if char == ':' and depth == 0:
            parts.append(current)
            current = ''
        else:
            current += char
    if depth != 0:
        raise ValueError('unclosed [ in %r' % text)
    parts.append(current)
    return parts


def _strip_brackets(text):
    if text.startswith('[') and text.endswith(']'):
        return text[1:-1]
    return text


# --------------------------------------------------------------------------- #
# The state directory
# --------------------------------------------------------------------------- #

def state_dir(explicit=None, environ=None):
    """Where the server keeps its key, by the order in the plan's 1.3."""
    environ = os.environ if environ is None else environ
    if explicit:
        return os.path.abspath(os.path.expanduser(explicit))
    from_env = environ.get(ENV_STATE_DIR)
    if from_env:
        return os.path.abspath(os.path.expanduser(from_env))
    xdg = environ.get('XDG_STATE_HOME')
    if xdg:
        return os.path.join(os.path.abspath(os.path.expanduser(xdg)),
                            'fteproxy')
    return os.path.expanduser(os.path.join('~', '.local', 'state', 'fteproxy'))


def ensure_state_dir(path):
    """Create the state directory at mode 0700, tightening it if it is looser.

    A directory another local user can read is a directory they can read the
    private key out of, so a pre-existing loose one is corrected rather than
    accepted.
    """
    try:
        os.makedirs(path, mode=DIR_MODE, exist_ok=True)
        current = stat.S_IMODE(os.stat(path).st_mode)
        if current & 0o077:
            os.chmod(path, DIR_MODE)
    except OSError as e:
        raise ConfigError('cannot use state directory %s: %s' % (path, e))
    return path


def _write_private(path, text):
    """Write ``text`` to ``path`` at mode 0600, creating it exclusively."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, FILE_MODE)
    try:
        os.chmod(path, FILE_MODE)
        with os.fdopen(descriptor, 'w') as handle:
            handle.write(text)
    except Exception:
        os.close(descriptor)
        raise


def server_key_path(directory):
    return os.path.join(directory, SERVER_KEY_FILE)


def connection_path(directory):
    return os.path.join(directory, CONNECTION_FILE)


def load_server_key(directory):
    """Read ``server.key``, or None if it is not there.

    Warns when the file is readable by anyone else: a key that has been world
    readable should be replaced, not silently used.
    """
    path = server_key_path(directory)
    try:
        with open(path) as handle:
            text = handle.read().strip()
    except FileNotFoundError:
        return None
    except OSError as e:
        raise ConfigError('cannot read %s: %s' % (path, e))
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        mode = 0
    if mode & 0o077:
        fteproxy.warn('%s is readable by other users (mode %o); '
                      'fix it with chmod 600 and consider generating a new key'
                      % (path, mode))
    if len(text) != 64:
        raise ConfigError('%s should hold 64 hex characters, found %d'
                          % (path, len(text)))
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise ConfigError('%s is not hexadecimal' % path)


def save_server_key(directory, private_bytes):
    path = server_key_path(directory)
    try:
        _write_private(path, private_bytes.hex() + '\n')
    except OSError as e:
        raise ConfigError('cannot write %s: %s' % (path, e))
    return path


def ensure_server_key(directory):
    """Return ``(private, public, created)``, generating a key on first use."""
    private = load_server_key(directory)
    if private is not None:
        return private, fteproxy.server_id(private), False
    private, public = fteproxy.generate_server_key()
    save_server_key(directory, private)
    return private, public, True


def write_connection_string(directory, uri):
    path = connection_path(directory)
    try:
        _write_private(path, uri.format() + '\n')
    except OSError as e:
        raise ConfigError('cannot write %s: %s' % (path, e))
    return path


def read_connection_string(directory):
    """The connection string from ``connection.txt``, or None."""
    path = connection_path(directory)
    try:
        with open(path) as handle:
            text = handle.read().strip()
    except FileNotFoundError:
        return None
    except OSError as e:
        raise ConfigError('cannot read %s: %s' % (path, e))
    return text or None


def resolve_client_uri(argument=None, directory=None, environ=None):
    """The client's URI, from the argument, the environment, or the file.

    Returns ``(ConnectionString, source)``. A string that still carries the
    ``<server-ip>`` placeholder can only have been written by a server on this
    host, so it is pointed at loopback; that is what makes ``fteproxy server``
    then ``fteproxy client`` work on one machine with no arguments at all.
    """
    environ = os.environ if environ is None else environ
    if argument:
        text, source = argument, 'the command line'
    elif environ.get(ENV_URI):
        text, source = environ[ENV_URI], ENV_URI
    elif directory is not None:
        text = read_connection_string(directory)
        source = connection_path(directory)
        if not text:
            return None, None
    else:
        return None, None

    uri = ConnectionString.parse(text)
    if uri.host == HOST_PLACEHOLDER:
        uri = uri.with_host('127.0.0.1')
    return uri, source
