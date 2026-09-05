# fteproxy

[![Tests](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml/badge.svg)](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml)
[![PyPI version](https://img.shields.io/pypi/v/fteproxy.svg)](https://pypi.org/project/fteproxy/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/kpdyer/fteproxy/blob/main/LICENSE)

fteproxy tunnels TCP streams through Format-Transforming Encryption (FTE).
Applications use SOCKS5 or a local port forward; encrypted records between the
client and server use a selected regular-expression format.

The CLI below requires fteproxy 1.0 and Python 3.10 or newer. For a published
1.0 release:

```bash
python3 -m pip install "fteproxy>=1.0,<1.1"
```

To use a 1.0 source checkout, run `python3 -m pip install -e .` from its root.
An older PyPI release does not provide the CLI shown here.

> **1.0 is not wire-compatible with 0.3.x.**
> Upgrade both endpoints together and follow the
> [upgrade guide](https://github.com/kpdyer/fteproxy#upgrading-to-100).

## Quick start

On the server, use the address remote clients can reach:

```bash
fteproxy server --advertise vpn.example.com:8080
```

The first start creates an X25519 keypair and a mode-0600 `connection.txt`
in `~/.local/state/fteproxy` by default. Startup output reports the actual
paths. Copy `connection.txt` securely to the client, then run:

```bash
fteproxy client --connection-file ./connection.txt
```

The client checks the server handshake and serves SOCKS5 on
`127.0.0.1:1080`. In another terminal:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

This sends the destination name through the tunnel for the server to resolve.
Applications that resolve names themselves can still make local DNS queries.

Prefer `--connection-file`, `--connection-stdin`, or the implicit state
file; a positional URI can appear in process listings or shell history.
A normal server start stores the URI without printing it. `keygen` and
`server --print-connection` print it deliberately.

## Forwarding and formats

`-L [BIND:]PORT:HOST:PORT` creates a fixed forward;
`-D [BIND:]PORT` creates a SOCKS5 listener. Both are repeatable.
For example, `-L 2222:127.0.0.1:22` reaches SSH on the server host when
the server is started with `--allow 127.0.0.1:22`.

With no allow rules, the server dials only globally routable unicast addresses.
Only explicit IP/CIDR rules permit private or other non-global destinations;
`--allow any` alone does not. Local listeners require literal loopback binds
unless `--expose-listeners` is set. They have no client authentication.

The default release contains `http`, `ftp`, `smtp`, `sip`, and DNS over
TCP. The CLI chooses a format from the server port, falling back to `http`,
and uses the format's mode hint unless a flag or URI hint overrides it.
`fteproxy formats` lists the choices.

HTTP defaults to `hybrid`: a 200-byte FTE header followed by authenticated
ciphertext in one HTTP chunk and a terminal zero chunk. Other formats default
to `format`, which transforms each complete record, apart from any external
length prefix, at lower throughput.

Matching a format targets signature and keyword filters. It does not hide
traffic timing, volume, random field values, or inconsistent request/response
conversations. HTTP requires a direct TCP path that preserves bytes; HTTP
proxies that rewrite headers or rechunk bodies are unsupported.

Run `fteproxy help` or `fteproxy help client` for command help.
See the [documentation](https://github.com/kpdyer/fteproxy),
[security model](https://github.com/kpdyer/fteproxy/blob/main/SECURITY.md),
and [FTE paper](https://kpdyer.com/publications/ccs2013-fte.pdf).
Licensed under MIT.
