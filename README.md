# fteproxy

[![Tests](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml/badge.svg)](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/fteproxy.svg)](https://pypi.org/project/fteproxy/)

* Homepage: https://github.com/kpdyer/fteproxy
* Source code: https://github.com/kpdyer/fteproxy
* Publication: https://kpdyer.com/publications/ccs2013-fte.pdf

## Overview

fteproxy provides transport-layer protection to resist keyword filtering, censorship and discriminatory routing policies.
Its job is to relay datastreams, such as web browsing traffic, by encoding the stream into messages that satisfy a user-specified regular expression.

fteproxy is powered by Format-Transforming Encryption [1] and was presented at CCS 2013.

> **fteproxy 1.0 is not wire-compatible with 0.3.x, and its command line has
> changed.** Upgrade both endpoints together and see
> [Upgrading to 1.0.0](#upgrading-to-100).

[1] [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf), Kevin P. Dyer, Scott E. Coull, Thomas Ristenpart and Thomas Shrimpton

## Requirements

- Python 3.10 or higher
- [libfte](https://github.com/kpdyer/libfte) 0.4.x (`fte>=0.4.0,<0.5.0`) and
  `cryptography>=42.0`, both installed automatically by `pip`. `cryptography`
  is a compiled package; wheels exist on PyPI for every supported platform.

## Installation

### From PyPI

```bash
pip install fteproxy
```

### From Source

```bash
git clone https://github.com/kpdyer/fteproxy.git
cd fteproxy
pip install -e ".[test]"
```

The `[test]` extra adds `pytest` and `pytest-timeout`; drop it (`pip install -e .`)
if you only want to run fteproxy. Every dependency, including that extra, is
declared in `pyproject.toml` -- there is no `requirements.txt`.

## Usage

### Start the server

Once per host. The first start generates the server's keypair and prints the
connection string clients need:

```console
$ fteproxy server
listening on [::]:8080
key: ~/.local/state/fteproxy/server.key (created)
allowing: every destination except the loopback and link-local addresses of this host
clients connect with:
  fteproxy client fte://Qm3s…ZzE@<server-ip>:8080?defs=20260110
(also written to ~/.local/state/fteproxy/connection.txt)
```

Substitute the address your clients will dial for `<server-ip>`, or pass
`--advertise your.host:8080` and the string comes out ready to hand over.

### Start the client

On the client machine, with the string the server printed:

```console
$ fteproxy client fte://Qm3s…ZzE@203.0.113.5:8080
checking 203.0.113.5:8080 ... ok (protocol 1, manual-http, hybrid)
SOCKS5 on 127.0.0.1:1080

$ curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

The client resolves nothing itself: names go through the tunnel and the server
resolves them, so your DNS does not leak around the proxy.

The client checks the server before it binds anything, so a wrong connection
string fails in a round trip with a reason rather than as a timeout on the
first real connection:

```console
$ fteproxy client fte://…@203.0.113.5:8080
checking 203.0.113.5:8080 ... failed: no valid handshake reply within 5s
  (wrong connection string, or the server is not running fteproxy 1.0)
$ echo $?
1
```

Pass `--no-check` to skip it.

On one host you can leave the argument out entirely — the client reads
`connection.txt` from the state directory:

```bash
fteproxy server &
fteproxy client
```

### A port forward instead of SOCKS

`-L` takes ssh's spelling, and is how you reproduce the fixed-destination
topology fteproxy had before 1.0:

```bash
fteproxy client fte://…@203.0.113.5:8080 -L 2222:127.0.0.1:22
ssh -p 2222 user@localhost
```

`-L` and `-D` are repeatable and can be mixed; without either, the client
opens SOCKS5 on `127.0.0.1:1080`.

### What the server will dial

By default a server will reach any destination *except* its own loopback and
link-local addresses, checked both on what the client asked for and on what
the name resolved to. That keeps a connection string from being a route into
the server's own admin interfaces.

`--allow` replaces that policy with a list:

```bash
fteproxy server --allow 127.0.0.1:8081          # only this local service
fteproxy server --allow '*.example.com:443'     # only this domain, only TLS
fteproxy server --allow 10.0.0.0/8              # only this network
fteproxy server --allow any                     # everything, loopback included
```

Rules are repeatable. A rule naming an address is matched against addresses
and CIDRs; a rule naming a name is matched against names. IPv6 literals go in
brackets when a port follows.

### Formats and record-layer modes

A *format* is a base name from the definitions file, such as `manual-http`;
the request and response covertexts are derived from it. `fteproxy formats`
lists them with the capacity of one covertext:

```console
$ fteproxy formats
name          req len  req cap  resp len  resp cap
...
manual-http       256      150       256       192  (default)
words             280      138       280       138
```

The client picks the format and the record-layer mode and puts both in the
handshake; the server follows. Nothing has to be configured to match.

- `--mode hybrid` (default): each record is a fixed-length covertext header
  followed by raw authenticated ciphertext. Fast — hundreds of MB/s — but only
  the header blends in with the target protocol.
- `--mode format`: every byte on the wire is in the format, so the whole
  stream is indistinguishable from the protocol. Much slower (well under
  1 MB/s), for deployments facing entropy or statistical detectors.

### Command line

```
fteproxy server  [--listen [HOST]:PORT] [--allow RULE]... [--advertise HOST[:PORT]]
                 [--state-dir DIR] [--defs RELEASE] [-q | -v]
fteproxy client  [URI] [-D [BIND:]PORT] [-L [BIND:]PORT:HOST:PORT]...
                 [--format NAME] [--mode hybrid|format] [--no-check]
                 [--state-dir DIR] [-q | -v]
fteproxy keygen  [--state-dir DIR] [--advertise HOST[:PORT]]
fteproxy formats [--defs RELEASE]
fteproxy --version
```

| Option | Command | Description | Default |
|--------|---------|-------------|---------|
| `--listen` | server | Address to listen on; `:PORT` means every interface, IPv6 in brackets | `:8080` |
| `--allow` | server | A destination clients may reach; repeatable | loopback and link-local blocked, everything else allowed |
| `--advertise` | server, keygen | The address to put in the connection string | a `<server-ip>` placeholder |
| `--defs` | server, formats | Definitions release, as YYYYMMDD | 20260110 |
| `URI` | client | `fte://SERVER-ID@HOST:PORT`; falls back to `$FTEPROXY_URI`, then `connection.txt` | |
| `-D` | client | SOCKS5 listener, `[BIND:]PORT` | `127.0.0.1:1080` when no `-D`/`-L` |
| `-L` | client | Forward `[BIND:]PORT` to one `HOST:PORT` through the tunnel; repeatable | |
| `--format` | client | Base format name (see `fteproxy formats`) | the URI's hint, else `manual-http` |
| `--mode` | client | `hybrid` or `format` | the URI's hint, else `hybrid` |
| `--no-check` | client | Skip the startup check | check runs |
| `--state-dir` | all | Where `server.key` and `connection.txt` live | `$FTEPROXY_STATE_DIR`, `$XDG_STATE_HOME/fteproxy`, `~/.local/state/fteproxy` |
| `-q` / `-v` | all | Errors only / per-connection detail | INFO |
| `--version` | | Version and licence, then quit | |

Exit status is 0 on a clean shutdown, 1 on a runtime failure, 2 on a usage
error. The process runs in the foreground and stops on SIGINT or SIGTERM;
there is no daemon mode and no PID file.

### Keys and the connection string

The server holds an X25519 private key in `server.key` (mode 0600, in a
directory with mode 0700). The connection string carries only its public half,
so a client never holds anything that would let it impersonate the server.

`fteproxy keygen` does what the first `fteproxy server` start does, without
starting anything — for provisioning a container or a configuration-management
run:

```bash
fteproxy keygen --advertise vpn.example.com:8080
```

Treat the connection string like a Tor bridge line: whoever holds it can
connect, and its secrecy is what stops an active prober from confirming that
your server is running fteproxy. A prober without it gets no reply at all. It
does not let its holder impersonate the server or read another client's
traffic. See [SECURITY.md](SECURITY.md).

### Python API

```python
import fteproxy

private, public = fteproxy.generate_server_key()

# server side
sock = fteproxy.wrap_socket(conn, server_key=private)
destination = sock.wait_open()      # (host, port), or None if the peer sent data
sock.open_result(0x00)

# client side
sock = fteproxy.wrap_socket(raw, server_id=public,
                            format="manual-http", mode="hybrid")
sock.connect(("203.0.113.5", 8080))
sock.open(("example.com", 443))     # raises fteproxy.OpenRefused(status)
```

`fteproxy.ConnectionString.parse(text)` and `.format()` round-trip the URI. The
[`examples/`](examples/README.md) directory has programmatic, chat,
file-transfer and integration examples.

## Upgrading to 1.0.0

1.0.0 changes the wire format, the command line and the topology. There is no
compatibility mode: a 0.3.x peer, or a peer running an earlier development
build, gets no reply at all. The full notes are in
[docs/release-notes-1.0.0.md](docs/release-notes-1.0.0.md).

- **The command line is new.** Every old flag (`--mode`, `--server_ip`,
  `--client_port`, `--proxy_ip`, `--proxy_port`, `--key`, `--key-file`,
  `--upstream-format`, `--downstream-format`, `--record-layer-mode`,
  `--release`, `--stop`, `--quiet`) is recognised only to print a pointer here
  and exit 2. None of them is aliased, because the meaning changed rather than
  the spelling.
- **The topology changed: the destination is chosen on the client.** The
  server no longer has a forward address, so `--proxy_ip`/`--proxy_port` have
  no equivalent on the server. The old setup

  ```bash
  # 0.3
  fteproxy --mode server --server_port 8080 --proxy_ip 127.0.0.1 --proxy_port 22
  fteproxy --mode client --client_port 8079 --server_ip S --server_port 8080
  ```

  becomes

  ```bash
  # 1.0
  fteproxy server --listen :8080 --allow 127.0.0.1:22
  fteproxy client fte://…@S:8080 -L 8079:127.0.0.1:22
  ```

  and the same server now also serves `-D` SOCKS5 clients, without being
  reconfigured.
- **The shared key is gone.** So are `--key` and `--key-file`. The server has a
  keypair instead, generated on first start; hand clients the connection string
  it prints. Nothing needs a pre-shared secret, and there is no public default
  key to forget to replace.
- **Formats and modes are negotiated, not configured.** One `--format` base
  name on the client replaces `--upstream-format`/`--downstream-format`, and
  `--mode` replaces `--record-layer-mode` on one side only. A mismatch is no
  longer possible.
- **Failures are visible.** The client checks the server at startup and prints
  a reason; a wrong connection string fails in a round trip instead of hanging.
  Exit statuses are meaningful (0/1/2), and a no-argument run prints usage
  instead of crashing.
- **Definitions.** Thirty-two entries in `20260110.json` have longer
  covertexts, so that every shipped format can carry a handshake; the loader
  now refuses a release with a format that cannot. The default `manual-http-*`
  formats are unchanged at length 256, carrying 150 (request) and 192
  (response) bytes.
- **API.** `wrap_socket`'s `outgoing_regex`/`incoming_regex`/`K1`/`K2`/
  `negotiate` parameters are replaced by `server_key=` or `server_id=` plus
  `format=`/`mode=`. See [Python API](#python-api).
- **Requires** `fte>=0.4.0,<0.5.0` and `cryptography>=42.0`.

See [SECURITY.md](SECURITY.md) for the security model, including what the
handshake and the record layer do and do not authenticate.

## Testing

```bash
python -m pytest fteproxy/tests/ -v
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

Kevin P. Dyer (kpdyer@gmail.com)
