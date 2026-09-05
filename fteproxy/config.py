#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Connection capabilities, address syntax, and private state files.

A URI carries a canonical base64url X25519 server ID, host/port, and optional
format, mode, and dated definitions hints. Unknown query keys are ignored.
CLI format/mode flags override those hints; the definitions hint selects the
client's release. Treat the URI as a secret connection capability.

State directory precedence: explicit argument, FTEPROXY_STATE_DIR,
XDG_STATE_HOME/fteproxy, then ~/.local/state/fteproxy.
"""

import ipaddress
import os
import re
import stat
import urllib.parse
from contextlib import contextmanager

import fteproxy
import fteproxy.handshake
import fteproxy.key_codec


SCHEME = 'fte'
DEFAULT_PORT = 8080

SERVER_KEY_FILE = 'server.key'
CONNECTION_FILE = 'connection.txt'

#: Legacy placeholder accepted only in an implicit same-host connection file.
#: New server and keygen output always contains a valid address; keep this
#: sentinel solely so state written by an earlier 1.0 build still works locally.
HOST_PLACEHOLDER = '<server-ip>'

#: Directory mode 0700 and file mode 0600: the private key and the connection
#: string are both secrets, and a state directory readable by other local users
#: hands them over.
DIR_MODE = 0o700
FILE_MODE = 0o600

ENV_STATE_DIR = 'FTEPROXY_STATE_DIR'
ENV_URI = 'FTEPROXY_URI'

# A connection string is a single small capability, not an input document.
# Bounding file/stdin reads avoids turning a convenience option into an
# accidental unbounded allocation or pipe sink.
MAX_CONNECTION_STRING_BYTES = 4096

_DATED_RELEASE = re.compile(r'^[0-9]{8}$')


class ConfigError(Exception):
    """A connection string or a state directory that cannot be used."""


# --------------------------------------------------------------------------- #
# Server identity encoding
# --------------------------------------------------------------------------- #

def encode_server_id(public_bytes):
    """32 bytes -> the 43-character base64url server-id."""
    try:
        return fteproxy.key_codec.encode_server_id(public_bytes)
    except (TypeError, ValueError) as exc:
        raise ConfigError(str(exc)) from exc


def decode_server_id(text):
    """The 43-character base64url server-id -> 32 bytes."""
    try:
        return fteproxy.key_codec.decode_server_id(text)
    except (TypeError, ValueError) as exc:
        raise ConfigError(str(exc)) from exc


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
        if not isinstance(host, str) or not host:
            raise ConfigError('a connection string needs a host')
        # Construction is public API, not just an internal sequel to parse().
        # Keep str()/repr() single-line and keep authority delimiters from
        # turning a host into userinfo, path, query or fragment.  The sentinel
        # remains constructible solely for reading legacy same-host state.
        if (host != HOST_PLACEHOLDER
                and any(char in '@/\\?#<>[]' or char.isspace()
                        or ord(char) < 0x20 or 0x7f <= ord(char) <= 0x9f
                        for char in host)):
            raise ConfigError('connection string host contains unsafe '
                              'characters')
        if (not isinstance(port, int) or isinstance(port, bool)
                or not 0 < port <= 0xFFFF):
            raise ConfigError('connection string port is out of range')
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
        if len(text.encode('utf-8', errors='replace')) \
                > MAX_CONNECTION_STRING_BYTES:
            raise ConfigError('connection string is too long')
        if any(ord(char) < 0x20 or 0x7f <= ord(char) <= 0x9f
               or char.isspace() for char in text):
            raise ConfigError('connection string must be one line without '
                              'whitespace or control characters')
        try:
            parsed = urllib.parse.urlsplit(text)
        except ValueError:
            # urlsplit raises on, for instance, an unbalanced [ in the
            # authority. That is a malformed connection string like any other,
            # not a bug, so it gets a usage error rather than a traceback --
            # and, like every other message here, without the string in it.
            raise ConfigError('connection string is not a valid URI') from None
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
        except ValueError:
            # split_host_port's own messages quote what they were given,
            # which is fine for a --listen flag and not for a connection
            # string: the host and port are part of the secret.
            raise ConfigError(
                'connection string has an invalid host or port') from None
        if not host:
            raise ConfigError('a connection string needs a host')

        hints = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        mode = hints.get('mode', [None])[0]
        if mode is not None and mode not in fteproxy.handshake.MODES:
            raise ConfigError('mode hint must be one of %s'
                              % ', '.join(fteproxy.handshake.MODES))
        defs = hints.get('defs', [None])[0]
        if defs is not None and _DATED_RELEASE.fullmatch(defs) is None:
            raise ConfigError('defs hint must be a YYYYMMDD release')
        return cls(server_id=server_id, host=host, port=port,
                   format_name=hints.get('format', [None])[0], mode=mode,
                   defs=defs)

    # -- rendering --------------------------------------------------------- #

    def format(self):
        """Serialize recognized fields to a URI; unknown parameters are not retained."""
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
        """Return a copy with a new host and optional port, preserving its hints."""
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
        # Several colons and no brackets: only a bare IPv6 literal belongs
        # here (a host name cannot contain a colon), and ::1:8080 is a
        # complete address, so a port never follows a bare literal.
        try:
            ipaddress.IPv6Address(text)
        except ValueError:
            raise ValueError('%r is neither host:port nor an IPv6 literal; '
                             'write an IPv6 literal with a port as [addr]:port'
                             % text)
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
    bind = _strip_brackets(bind)
    host = _strip_brackets(host)
    if not host:
        raise ValueError('destination host is empty in %r' % text)
    return ((bind, _parse_port(local_port, text)),
            (host, _parse_port(port, text)))


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
    """Resolve explicit, FTEPROXY_STATE_DIR, XDG_STATE_HOME, then home fallback."""
    environ = os.environ if environ is None else environ
    if explicit is not None:
        if not isinstance(explicit, str) or not explicit:
            raise ConfigError('an explicit state directory must not be empty')
        expanded = os.path.expanduser(explicit)
        if expanded.startswith('~'):
            raise ConfigError('state directory refers to an unknown user')
        return os.path.abspath(expanded)
    from_env = environ.get(ENV_STATE_DIR)
    if from_env:
        return os.path.abspath(os.path.expanduser(from_env))
    xdg = environ.get('XDG_STATE_HOME')
    if xdg:
        return os.path.join(os.path.abspath(os.path.expanduser(xdg)),
                            'fteproxy')
    return os.path.expanduser(os.path.join('~', '.local', 'state', 'fteproxy'))


def validate_state_dir(path, missing_ok=False):
    """Validate an existing state directory without changing it.

    Refusing a loose or symlinked directory is deliberate. A privileged typo
    such as ``--state-dir /var/lib`` must not chmod an unrelated tree, and a
    state-directory symlink makes the destination of private writes less
    obvious than this security boundary should be.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return False
        raise ConfigError('state directory %s does not exist' % path)
    except OSError as e:
        raise ConfigError('cannot use state directory %s: %s' % (path, e))

    if stat.S_ISLNK(info.st_mode):
        raise ConfigError('state directory %s must not be a symlink' % path)
    if not stat.S_ISDIR(info.st_mode):
        raise ConfigError('state directory %s is not a directory' % path)

    getuid = getattr(os, 'geteuid', None)
    if getuid is not None and info.st_uid != getuid():
        raise ConfigError('state directory %s is owned by uid %d, not uid %d'
                          % (path, info.st_uid, getuid()))

    current = stat.S_IMODE(info.st_mode)
    if current & 0o077:
        raise ConfigError(
            'state directory %s has mode %o; run chmod 700 %s explicitly '
            'before using it' % (path, current, path))
    return True


def ensure_state_dir(path):
    """Create a missing state directory at mode 0700, or validate one.

    An existing directory is never chmodded implicitly; see
    :func:`validate_state_dir`.
    """
    if validate_state_dir(path, missing_ok=True):
        return path
    try:
        os.makedirs(path, mode=DIR_MODE, exist_ok=False)
    except FileExistsError:
        # A concurrent creator won the race. Validate exactly what appeared.
        validate_state_dir(path)
        return path
    except OSError as e:
        raise ConfigError('cannot create state directory %s: %s' % (path, e))
    validate_state_dir(path)
    return path


@contextmanager
def _private_temporary(path, text):
    """Yield a complete, synced mode-0600 sibling file and clean it up on exit."""
    directory = os.path.dirname(path) or os.curdir
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, 'O_NOFOLLOW', 0))
    temporary = os.path.join(
        directory, '.%s.%s.tmp' % (os.path.basename(path),
                                   os.urandom(8).hex()))
    descriptor = os.open(temporary, flags, FILE_MODE)
    try:
        try:
            handle = os.fdopen(descriptor, 'w')
        except BaseException:
            # Until fdopen succeeds, the descriptor is still ours to close.
            os.close(descriptor)
            raise
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        yield temporary
    finally:
        _remove_quietly(temporary)


def _write_private(path, text):
    """Atomically replace path with complete mode-0600 text.

    Renaming a fresh sibling replaces a target symlink rather than following it.
    The caller must provide a trusted parent directory.
    """
    with _private_temporary(path, text) as temporary:
        os.replace(temporary, path)


def _write_private_if_absent(path, text):
    """Atomically publish ``text`` at ``path`` only if it is absent.

    The complete mode-0600 temporary file is hard-linked into place, an atomic
    no-overwrite operation. Unlike opening the canonical path with ``O_EXCL``,
    a concurrent reader can therefore never observe a half-written key.
    Returns ``True`` for the winner and ``False`` when another process won.
    """
    with _private_temporary(path, text) as temporary:
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            return False
    return True


def _remove_quietly(path):
    """Try to unlink path, ignoring OSError during cleanup."""
    try:
        os.unlink(path)
    except OSError:
        pass


def server_key_path(directory):
    return os.path.join(directory, SERVER_KEY_FILE)


def connection_path(directory):
    return os.path.join(directory, CONNECTION_FILE)


def _read_managed_text(path, maximum, missing_ok=False):
    """Read a bounded, trusted-state file without following a leaf symlink.

    ``server.key`` and the implicit ``connection.txt`` inherit trust from the
    private state directory.  That trust must not silently cross a symlink or a
    hard link into a file with a different owner.  ``O_NOFOLLOW`` closes the
    check/open race on platforms that provide it; the lstat/fstat comparison is
    retained both as a portable fallback and as a useful consistency check.
    Returns ``(text, stat_result)`` or ``(None, None)`` when ``missing_ok``.
    """
    nofollow = getattr(os, 'O_NOFOLLOW', 0)
    # O_NONBLOCK makes opening a FIFO/device safe even if the leaf is swapped
    # between lstat and open; regular-file reads retain their normal semantics.
    flags = (os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0)
             | getattr(os, 'O_NONBLOCK', 0) | nofollow)
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None, None
        raise ConfigError('managed state file %s does not exist' % path)
    except OSError as e:
        raise ConfigError('cannot inspect managed state file %s: %s'
                          % (path, e))
    if stat.S_ISLNK(before.st_mode):
        raise ConfigError('managed state file %s must not be a symlink' % path)
    if not stat.S_ISREG(before.st_mode):
        raise ConfigError('managed state file %s must be a regular file' % path)

    descriptor = None
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        after = os.lstat(path)
        if (stat.S_ISLNK(after.st_mode)
                or (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino)):
            raise ConfigError('managed state file %s changed while opening it'
                              % path)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError('managed state file %s must be a regular file'
                              % path)
        if info.st_nlink != 1:
            raise ConfigError('managed state file %s must not have hard links'
                              % path)
        getuid = getattr(os, 'geteuid', None)
        if getuid is not None and info.st_uid != getuid():
            raise ConfigError(
                'managed state file %s is owned by uid %d, not uid %d'
                % (path, info.st_uid, getuid()))

        handle = os.fdopen(descriptor, 'r', encoding='utf-8')
        descriptor = None              # the file object owns it from here
        with handle:
            return handle.read(maximum + 1), info
    except ConfigError:
        raise
    except FileNotFoundError:
        if missing_ok:
            return None, None
        raise ConfigError('managed state file %s does not exist' % path)
    except (OSError, UnicodeError) as e:
        raise ConfigError('cannot read managed state file %s: %s' % (path, e))
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _warn_connection_file_privacy(path, info):
    """Warn, but do not reject, an explicitly supplied capability file."""
    concerns = []
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077:
        concerns.append('readable by other users (mode %o; use chmod 600)'
                        % mode)
    getuid = getattr(os, 'geteuid', None)
    if getuid is not None and info.st_uid != getuid():
        concerns.append('owned by uid %d instead of uid %d'
                        % (info.st_uid, getuid()))
    if concerns:
        fteproxy.warn(
            '%s is not private: %s; protect it and rotate the connection '
            'capability if it may have been exposed'
            % (path, '; '.join(concerns)))


def load_server_key(directory):
    """Read a managed server.key, or None if absent.

    Loose permissions warn but do not prevent loading an otherwise valid key.
    """
    path = server_key_path(directory)
    text, info = _read_managed_text(path, 4096, missing_ok=True)
    if text is None:
        return None
    text = text.strip()
    mode = stat.S_IMODE(info.st_mode)
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
    """Return ``(private, public, created)``, generating a key on first use.

    The no-overwrite publication ensures concurrent first starts converge on
    one identity instead of alternately replacing ``server.key``.
    """
    private = load_server_key(directory)
    if private is not None:
        return private, fteproxy.server_id(private), False
    candidate, _public = fteproxy.generate_server_key()
    return claim_server_key(directory, candidate)


def claim_server_key(directory, candidate):
    """Install ``candidate`` only if no identity exists, then return the winner.

    This variant lets the server bind with an in-memory candidate before it
    creates first-run state. If another command publishes a key meanwhile, the
    caller sees that winner and can refuse to serve under a mismatched key.
    """
    private = load_server_key(directory)
    if private is not None:
        return private, fteproxy.server_id(private), False
    try:
        candidate = bytes(candidate)
        public = fteproxy.server_id(candidate)
        created = _write_private_if_absent(
            server_key_path(directory), candidate.hex() + '\n')
    except (TypeError, ValueError) as e:
        raise ConfigError('invalid server key: %s' % e)
    except OSError as e:
        raise ConfigError('cannot create %s: %s'
                          % (server_key_path(directory), e))
    if created:
        return candidate, public, True

    private = load_server_key(directory)
    if private is None:
        raise ConfigError('server.key appeared concurrently but could not be '
                          'read')
    return private, fteproxy.server_id(private), False


def write_connection_string(directory, uri):
    path = connection_path(directory)
    try:
        _write_private(path, uri.format() + '\n')
    except OSError as e:
        raise ConfigError('cannot write %s: %s' % (path, e))
    return path


def read_connection_string(directory):
    """The connection string from trusted state ``connection.txt``, or None."""
    path = connection_path(directory)
    text, info = _read_managed_text(
        path, MAX_CONNECTION_STRING_BYTES, missing_ok=True)
    if text is None:
        return None
    _warn_connection_file_privacy(path, info)
    return _bounded_connection_text(text)


def read_connection_file(path, missing_ok=False):
    """Read a bounded explicit connection file and warn about loose privacy.

    Errors omit its contents. Return None for an empty file, or for a missing file
    when missing_ok is True. Managed state uses read_connection_string instead.
    """
    try:
        with open(path) as handle:
            info = os.fstat(handle.fileno())
            text = handle.read(MAX_CONNECTION_STRING_BYTES + 1)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise ConfigError('connection file %s does not exist' % path)
    except (OSError, UnicodeError) as e:
        raise ConfigError('cannot read connection file %s: %s' % (path, e))
    _warn_connection_file_privacy(path, info)
    return _bounded_connection_text(text)


def _bounded_connection_text(text):
    """Return stripped connection text, rejecting an oversized source."""
    if len(text.encode('utf-8', errors='replace')) \
            > MAX_CONNECTION_STRING_BYTES:
        raise ConfigError('connection string is too long')
    return text.strip() or None


def resolve_client_uri(argument=None, directory=None, environ=None,
                       connection_file=None, input_stream=None):
    """Resolve the client's URI from one explicit source or a fallback.

    Explicit sources are the positional argument, ``connection_file`` and
    ``input_stream``; at most one may be present. With none, ``FTEPROXY_URI``
    and then the state directory's ``connection.txt`` are tried. Returns
    ``(ConnectionString, source)``.

    Only a legacy placeholder read implicitly from this host's
    ``connection.txt`` is pointed at loopback. A placeholder supplied through
    argv, the environment, an explicit file or stdin is incomplete and must
    not silently send the client to its own machine.
    """
    environ = os.environ if environ is None else environ
    explicit = sum(value is not None
                   for value in (argument, connection_file, input_stream))
    if explicit > 1:
        raise ConfigError('choose only one explicit connection source')

    from_implicit_file = False
    if argument is not None:
        text, source = argument, 'the command line'
    elif connection_file is not None:
        text = read_connection_file(connection_file)
        source = connection_file
    elif input_stream is not None:
        try:
            text = input_stream.read(MAX_CONNECTION_STRING_BYTES + 1)
        except (OSError, UnicodeError) as e:
            raise ConfigError('cannot read connection string from standard '
                              'input: %s' % e)
        text = _bounded_connection_text(text)
        source = 'standard input'
    elif environ.get(ENV_URI):
        text, source = environ[ENV_URI], ENV_URI
    elif directory is not None:
        if not validate_state_dir(directory, missing_ok=True):
            return None, None
        text = read_connection_string(directory)
        source = connection_path(directory)
        from_implicit_file = True
        if not text:
            return None, None
    else:
        return None, None

    if not text:
        raise ConfigError('empty connection string')
    uri = ConnectionString.parse(text)
    if uri.host == HOST_PLACEHOLDER:
        if not from_implicit_file:
            raise ConfigError(
                'connection string still contains <server-ip>; replace it '
                'with the server\'s reachable address')
        uri = uri.with_host('127.0.0.1')
    return uri, source
