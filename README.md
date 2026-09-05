# fteproxy

[![Tests](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml/badge.svg)](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/fteproxy.svg)](https://pypi.org/project/fteproxy/)

fteproxy tunnels TCP streams through Format-Transforming Encryption (FTE).
Applications connect through SOCKS5 or a local port forward. Between the client
and server, encrypted records use a selected regular-expression format.

FTE targets signature and keyword filters. Matching a format does not hide
traffic timing, volume, random field values, or inconsistent protocol
conversations. See the [security model](SECURITY.md).

> **1.0 is not wire-compatible with 0.3.x.**
> Upgrade both endpoints together; see [Upgrading to 1.0.0](#upgrading-to-100).

## Install

This guide describes the 1.0 checkout and requires Python 3.10 or newer.
From this repository's root, install it with test dependencies:

```bash
python3 -m pip install -e ".[test]"
```

Pip also installs `fte>=0.4.0,<0.5.0`, `regex2dfa>=0.2.0,<0.3.0`, and
`cryptography>=42.0`. To install a published 1.0 release when available:

```bash
python3 -m pip install "fteproxy>=1.0,<1.1"
```

The version constraint prevents installing an older release with a different
CLI. Use `python3 -m fteproxy` if the `fteproxy` command is not on your PATH.

## Quick start

On the server, replace `vpn.example.com` with the address clients can reach:

```bash
fteproxy server --advertise vpn.example.com:8080
```

The server listens on port 8080 and creates `server.key` and `connection.txt`
in its state directory. The default is `~/.local/state/fteproxy`; startup
output reports the actual paths. Copy `connection.txt` to the client through
a secure channel.

On the client:

```bash
fteproxy client --connection-file ./connection.txt
```

After checking the server handshake, the client serves SOCKS5 on
`127.0.0.1:1080`. In another terminal:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

`--socks5-hostname` sends the destination name through the tunnel for the
server to resolve. Applications that resolve names themselves can still make
local DNS queries; resolving the fteproxy server's own hostname also uses the
client's resolver.

### Connection input and state

Prefer `--connection-file FILE`, `--connection-stdin`, or the implicit state
file. A positional URI is supported but can appear in process listings and
shell history.

```bash
fteproxy client --connection-stdin < ./connection.txt
```

Explicit connection sources are mutually exclusive. With none, the client
checks `$FTEPROXY_URI`, then the state directory's `connection.txt`.
On one host, start `fteproxy server` and `fteproxy client` in separate
terminals; the client can use the server's file directly.

State directory precedence is `--state-dir`, `$FTEPROXY_STATE_DIR`,
`$XDG_STATE_HOME/fteproxy`, then `~/.local/state/fteproxy`.
New directories use mode 0700 and new key/connection files use mode 0600.
An existing directory with group or other permissions is refused; use
`chmod 700 DIR` on the intended directory before retrying. Managed reads
reject symlinks, hard links, non-regular files, and foreign ownership.
Loose file permissions warn. Writes publish complete files atomically without
following a symlink at the target.

A normal server start writes the URI without printing it. Use
`server --print-connection` to print it deliberately, or provision an identity
without starting a listener:

```bash
fteproxy keygen --advertise vpn.example.com:8080
```

`keygen` stores and prints the URI. Without `--advertise`, both commands
preserve an existing endpoint for the same identity. Otherwise the server uses
its concrete listen host, or loopback for a wildcard; `keygen` uses
`127.0.0.1:8080`. Reusing an endpoint also preserves its port, so supply
`--advertise` when changing the address clients should use.

### Port forwarding

To reach SSH on the server's loopback interface, allow that destination:

```bash
fteproxy server --advertise vpn.example.com:8080 --allow 127.0.0.1:22
```

On the client, using that server's connection file:

```bash
fteproxy client --connection-file ./connection.txt -L 2222:127.0.0.1:22
# In another terminal:
ssh -p 2222 user@127.0.0.1
```

`-L` / `--forward` accepts `[BIND:]PORT:HOST:PORT`; the destination is
interpreted on the server. `-D` / `--socks-listen` accepts `[BIND:]PORT`.
Both are repeatable and may be mixed. With neither, the default is SOCKS5 on
`127.0.0.1:1080`.

Local binds must be literal loopback addresses unless `--expose-listeners`
is set:

```bash
fteproxy client --connection-file ./connection.txt \
  -D 0.0.0.0:1080 --expose-listeners
```

These listeners have no client authentication. Anyone who can reach an exposed
port can use the tunnel; restrict access with the bind address and firewall.

### Destination policy

With no `--allow` rules, the server connects only to globally routable unicast
addresses. It excludes private, shared, loopback, link-local, unspecified,
reserved, documentation, and multicast ranges according to Python's address
classification.

Repeated `--allow` options replace the default with an allowlist:

| Rule | Effect |
|---|---|
| `--allow 127.0.0.1:8081` | Permit one local service |
| `--allow '*.example.com:443'` | Permit matching names on port 443, with globally routable results |
| `--allow 10.0.0.0/8` | Permit that private network on any port |
| `--allow any` | Permit any name or globally routable unicast address |

Only an explicit IP or CIDR rule permits a non-global address. A matching
address rule can also allow a hostname that resolves into that range.
Every candidate address is checked before dialing; rejected candidates are
skipped. IPv6 literals need brackets when followed by a port.

## Formats and modes

The default definitions release, `20260903`, contains five protocol-shaped
request/response pairs. Port metadata selects a format; it does not change the
server's listening port.

| Format | Port hints | Mode hint | Wire covertext lengths |
|---|---|---|---|
| `http` | 80, 8080, 8000 | `hybrid` | 200–700 bytes |
| `ftp` | 21 | `format` | 64–256 bytes |
| `smtp` | 25, 587 | `format` | 80–320 bytes |
| `sip` | 5060 | `format` | 300–800 bytes |
| `dns` | 53 | `format` | 90–272 bytes, including the TCP length prefix |

The CLI selects the format in this order: `--format`, the URI's `format`
hint, the server port's format, then `http`. It selects the mode in this
order: `--mode`, the URI's `mode` hint, the format's `mode_hint`, then
`hybrid`. An explicit format that disagrees with a recognized port is honored
with a warning. The client sends both choices in the handshake; both endpoints
must have matching definitions.

- **`hybrid`:** a fixed-length FTE header plus authenticated ciphertext.
  The header uses the shortest allowed length that holds it. HTTP uses
  200-byte headers and wraps the body in one HTTP chunk plus a terminal zero
  chunk. Other formats append the encrypted body directly.
- **`format`:** the whole record is format-transformed, apart from any
  external length prefix. Variable formats choose among up to eight lengths across
  their range, favoring shorter records for small messages and longer ones for
  queued bulk data. This costs more ranking work than hybrid.

The two handshake records always use the maximum length and the base regex.
For HTTP, these and format-mode records are zero-body messages. Hybrid data
uses separate POST/response headers with `Transfer-Encoding: chunked`.
The carrier requires a direct TCP path that preserves bytes: HTTP proxies that
rewrite headers or rechunk bodies are unsupported. Request and response records
are generated independently and need not form real HTTP transactions.

```bash
fteproxy formats
fteproxy defs-check
fteproxy formats --defs 20260110
```

The `cap` columns report cipher plaintext capacity. Format-mode application
payload capacity is 13 bytes smaller (12-byte seal plus record type).
The `hdr` column is the hybrid header's wire length, with request/response
values separated by a slash when they differ.

Release `20260110` retains 46 fixed-length shape entries (23 pairs), including
`manual-http`, `words`, and `base64`. Start the server with
`--defs 20260110`; its connection file supplies the release to the client.
`shapes-20260110` is a catalog alias for `formats` and `defs-check`;
server/keygen and URI release hints require eight digits.

## Command reference

Run `fteproxy help` or `fteproxy help COMMAND` for the full syntax.

| Command | Purpose |
|---|---|
| `server` | Accept tunnels and connect to allowed destinations |
| `client` | Serve local SOCKS5 listeners and fixed forwards |
| `keygen` | Create or reuse an identity; store and print its connection URI |
| `formats` | List a definitions release |
| `defs-check` | Validate a definitions release |
| `version` | Print the version and license notice |
| `help [COMMAND]` | Show help |

| Option | Commands | Default or meaning |
|---|---|---|
| `--listen [HOST]:PORT` | server | `:8080`; wildcard prefers dual-stack IPv6 with IPv4 fallback |
| `--allow RULE` | server | Repeatable destination rule; global unicast only with no rules |
| `--advertise HOST[:PORT]` | server, keygen | Address to put in the connection file |
| `--print-connection` | server | Also print the URI to stdout |
| `--defs RELEASE` | server, keygen, formats, defs-check | `20260903` |
| `--connection-file FILE`, `--connection-stdin`, or `URI` | client | Explicit connection source |
| `-D`, `--socks-listen [BIND:]PORT` | client | Repeatable SOCKS5 listener |
| `-L`, `--forward [BIND:]PORT:HOST:PORT` | client | Repeatable fixed forward |
| `--expose-listeners` | client | Permit non-loopback local binds |
| `--format NAME`, `--mode hybrid\|format` | client | Override URI and format defaults |
| `--no-check` | client | Skip the startup handshake check |
| `--max-pending N` | server, client | Concurrent setups: server 64, client 32 |
| `--max-pending-per-source N` | server, client | Setups per source IP: server 8, client 16 |
| `--max-active N` | server | Established relays: 128 |
| `--max-active-per-source N` | server | Established relays per source IP: 64 |
| `--state-dir DIR` | server, client, keygen | Override the state directory |
| `-q`, `-v` | server, client, keygen, formats, defs-check | Errors only / debug detail; otherwise INFO |

Limits must be positive. They bound concurrency, not connection rate or idle
duration. The client shares its setup limit across all local listeners.

The client validates and binds local listeners before its startup check.
A failed check exits 1 and may take the handshake timeout (five seconds by
default); it does not test a destination's reachability or allow rules.
Long options cannot be abbreviated. Exit status is 0 for success or clean
shutdown, 1 for runtime failure, and 2 for usage errors. Processes run in the
foreground and stop on SIGINT or SIGTERM.

## Python API

`fteproxy.wrap_socket` takes `server_key=` for the server role or
`server_id=` for the client role. Clients may also pass `format=`, `mode=`,
and `defs=`. The API uses configured defaults rather than CLI port/mode-hint
selection.

Use `generate_server_key()` to create an identity, `server_id(private)` to
derive its public key, and `ConnectionString.parse(text)` / `.format()` to
parse or serialize a URI. These preserve recognized fields, not arbitrary URI
spelling or unknown query parameters.

The [programmatic examples](examples/programmatic/README.md) show socket
wrapping, direct libfte encoding, and file transfer. Relay applications use
`open((host, port))`, `wait_open()`, and `open_result(status)`; opening a
wrapped socket alone does not dial an application destination.

## Upgrading to 1.0.0

1. Upgrade both endpoints together. There is no 0.3.x compatibility mode.
2. Start the server with a reachable `--advertise` address and any required
   `--allow` rules. Securely distribute its new `connection.txt`.
3. Replace the old client's fixed destination with `-L`; see
   [Port forwarding](#port-forwarding).
4. Replace shared-key API parameters with `server_key=` or `server_id=`.
   Old shared-key files are no longer used.

The old top-level `--mode client|server`, address flags, shared-key flags,
directional format flags, `--release`, `--stop`, and `--quiet` are removed.
The new `client --mode hybrid|format` selects the record mode.
`--version` remains an alias for `version`. There is no daemon mode or PID
file. See the [release notes](docs/release-notes-1.0.0.md) for details.

## Development and reference

```bash
python3 -m pytest --timeout=300
```

- [Examples](examples/README.md)
- [Format authoring](docs/format-authoring.md)
- [Security and vulnerability reporting](SECURITY.md)
- [Performance measurements](PERFORMANCE.md)
- [1.0 design history](docs/plan-1.0.md) and [format design history](docs/plan-formats.md)
- [UDP feasibility study](docs/udp-feasibility.md) — UDP is not implemented
- [FTE paper, CCS 2013](https://kpdyer.com/publications/ccs2013-fte.pdf)

MIT license; see [LICENSE](LICENSE). Original author: Kevin P. Dyer.
