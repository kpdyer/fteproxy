# fteproxy

[![Tests](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml/badge.svg)](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml)
[![PyPI version](https://img.shields.io/pypi/v/fteproxy.svg)](https://pypi.org/project/fteproxy/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**fteproxy** provides transport-layer protection to resist keyword filtering, censorship, and discriminatory routing policies using Format-Transforming Encryption (FTE).

## Installation

```bash
pip install fteproxy
```

> **1.0 is not wire-compatible with 0.3.x, and its command line has changed.**
> Every old flag now prints a pointer and exits 2; see
> [Upgrading to 1.0.0](https://github.com/kpdyer/fteproxy#upgrading-to-100).

## Quick Start

### Server

Once per host. The first start generates the server's keypair and a mode-0600
connection file:

```console
$ fteproxy server --advertise your.host:8080
listening on [::]:8080
key: ~/.local/state/fteproxy/server.key (created)
allowing: globally routable unicast destinations
connection string written to ~/.local/state/fteproxy/connection.txt
```

A normal server start does not print the connection URI because it is a
capability. Add `--print-connection` only when stdout is the intended secret
transport. Without `--advertise`, an existing endpoint for the same server
identity is preserved; a new URI uses loopback for same-host use rather than an
editable placeholder.

### Client

```console
$ fteproxy client --connection-file ./connection.txt
checking your.host:8080 ... ok (protocol 1, http, hybrid)
SOCKS5 on 127.0.0.1:1080

$ curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

Prefer `--connection-file` or `--connection-stdin`: a positional URI remains
supported, but can leak through process listings or shell history.

`-L`/`--forward 2222:127.0.0.1:22` gives an ssh-style port forward instead of
SOCKS5; `-D`/`--socks-listen` selects a SOCKS listener. Both default to
loopback, and an explicit bind must be a literal loopback address unless
`--expose-listeners` is present. Because there is no SOCKS authentication,
anyone who can reach an exposed listener can use the tunnel.

## How It Works

```
[Application] <-SOCKS5 or -L-> [fteproxy client] <--FTE encoded--> [fteproxy server] -> [Destination]
```

fteproxy encodes traffic to match user-specified regular expressions, making it
appear as allowed traffic (for example HTTP) to network filters. The client
picks the format and the framing mode and puts both in the handshake, so
nothing has to be configured to match. `--mode format` puts every covertext
byte in the selected format at much lower throughput. `--mode hybrid` (the
default) formats a header per record and carries authenticated ciphertext as
the body. HTTP uses complete zero-body messages for its handshake and format
mode, then switches to `POST`/`Transfer-Encoding: chunked` headers for hybrid
data: one ciphertext chunk followed by the terminal zero chunk.

The HTTP carrier requires a byte-preserving direct TCP path; it is not an HTTP
proxy protocol, and an intermediary that rewrites headers or rechunks a body
will make authentication fail. Each request and response is also generated
independently from tunneled traffic, so their counts and fields need not form
real HTTP transactions. The format targets signature and keyword filters, not
a stateful HTTP semantic classifier.

The destination travels in band, so one server serves SOCKS5 clients and port
forwards alike. With no `--allow` rules, the server dials only globally
routable unicast addresses. Rules form a whitelist, and only an explicit IP or
CIDR rule opts a private or other non-global result in; `--allow any` alone
still applies the safe address classification after DNS. The server
authenticates itself with an X25519 keypair; clients hold only the public half,
in the connection string.

## Links

- **Documentation:** https://github.com/kpdyer/fteproxy
- **Homepage:** https://github.com/kpdyer/fteproxy
- **Publication:** [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf) (CCS 2013)

## License

MIT License
