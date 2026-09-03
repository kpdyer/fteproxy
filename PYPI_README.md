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

Once per host. The first start generates the server's keypair and prints the
connection string clients need:

```console
$ fteproxy server --advertise your.host:8080
listening on [::]:8080
key: ~/.local/state/fteproxy/server.key (created)
clients connect with:
  fteproxy client fte://Qm3s…ZzE@your.host:8080?defs=20260903
```

### Client

```console
$ fteproxy client fte://Qm3s…ZzE@your.host:8080
checking your.host:8080 ... ok (protocol 1, http, hybrid)
SOCKS5 on 127.0.0.1:1080

$ curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

`-L 2222:127.0.0.1:22` gives an ssh-style port forward instead of SOCKS5.

## How It Works

```
[Application] <-SOCKS5 or -L-> [fteproxy client] <--FTE encoded--> [fteproxy server] -> [Destination]
```

fteproxy encodes traffic to match user-specified regular expressions, making it
appear as allowed traffic (for example HTTP) to network filters. The client
picks the format and the framing mode and puts both in the handshake, so
nothing has to be configured to match: `--mode hybrid` (the default) formats a
header per record and carries the body as raw authenticated ciphertext, and
`--mode format` puts every byte in the format at much lower throughput.

The destination travels in band, so one server serves SOCKS5 clients and port
forwards alike, and `--allow` decides which destinations it will dial. The
server authenticates itself with an X25519 keypair; clients hold only the
public half, in the connection string.

## Links

- **Documentation:** https://github.com/kpdyer/fteproxy
- **Homepage:** https://github.com/kpdyer/fteproxy
- **Publication:** [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf) (CCS 2013)

## License

MIT License
