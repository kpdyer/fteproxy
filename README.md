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

> **fteproxy 0.4 is not wire-compatible with 0.3.x.** Upgrade both endpoints
> together, give both the same key, and see [Upgrading to 0.4.0](#upgrading-to-040).

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
pip install -r requirements.txt
pip install -e .
```

## Usage

### Architecture

fteproxy operates as a client-server proxy:

```
[Application] <-> [fteproxy client] <--FTE encoded--> [fteproxy server] <-> [Destination]
```

### Start the Server

On the server machine:

```bash
python3 -m fteproxy --mode server --server_ip 0.0.0.0 --server_port 8080 --proxy_ip 127.0.0.1 --proxy_port 8081
```

This listens for FTE-encoded connections on port 8080 and forwards decoded traffic to 127.0.0.1:8081.

### Start the Client

On the client machine:

```bash
python3 -m fteproxy --mode client --client_ip 127.0.0.1 --client_port 8079 --server_ip <server-ip> --server_port 8080
```

This listens for plaintext connections on port 8079 and forwards FTE-encoded traffic to the server.

Both sides must use the same key (`--key` or `--key-file`; the built-in default
is public and fteproxy warns when it is in use) and the same
`--record-layer-mode`.

### Record-layer modes

Every record on the wire starts with a covertext in the chosen format. What
follows depends on `--record-layer-mode`, which must match on both endpoints:

- `hybrid` (default): the covertext is a fixed-length header and the rest of
  the record is raw authenticated ciphertext. Fast (hundreds of MB/s), but only
  the header blends in with the target protocol.
- `format`: every byte is transformed into the format, so the whole stream is
  indistinguishable from the protocol. Much slower (well under 1 MB/s), for
  deployments facing entropy or statistical detectors.

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--mode` | Relay mode: client or server | client |
| `--upstream-format` | Client-to-server format name (see `fteproxy/defs/20260110.json`) | manual-http-request |
| `--downstream-format` | Server-to-client format name | manual-http-response |
| `--record-layer-mode` | `hybrid` or `format` (see [Record-layer modes](#record-layer-modes)); must match on both endpoints | hybrid |
| `--release` | Definitions file to use, as YYYYMMDD | 20260110 |
| `--client_ip` | Client-side listening IP | 127.0.0.1 |
| `--client_port` | Client-side listening port | 8079 |
| `--server_ip` | Server-side listening IP | 127.0.0.1 |
| `--server_port` | Server-side listening port | 8080 |
| `--proxy_ip` | Forwarding-proxy listening IP | 127.0.0.1 |
| `--proxy_port` | Forwarding-proxy listening port | 8081 |
| `--key` | Shared secret (64 hex characters); must match on both endpoints. The built-in default is public and gives no protection. | (public default; warns) |
| `--key-file` | Path to a file containing the key (64 hex characters). Mutually exclusive with `--key`. | |
| `--quiet` | Suppress output | false |
| `--stop` | Shut down the running daemon for `--mode` | |
| `--version` | Show version and exit | |

### Supplying the Key from a File

Passing the key with `--key` places it in your shell history and exposes it in
process listings (e.g. `ps aux`). To avoid this, write the key to a file and
point fteproxy at it with `--key-file`:

```bash
# Generate a random 64-hex-character (32-byte) key
python3 -c "import secrets; print(secrets.token_hex(32))" > fteproxy.key
chmod 600 fteproxy.key
```

Then start each side with `--key-file` (the client and server must use the same
key):

```bash
python3 -m fteproxy --mode server --key-file fteproxy.key --server_ip 0.0.0.0 --server_port 8080 --proxy_ip 127.0.0.1 --proxy_port 8081
python3 -m fteproxy --mode client --key-file fteproxy.key --client_ip 127.0.0.1 --client_port 8079 --server_ip <server-ip> --server_port 8080
```

The file must contain exactly 64 hexadecimal characters (a trailing newline is
ignored). `--key` and `--key-file` cannot be used together.

### Python API

`fteproxy.wrap_socket(sock, outgoing_regex=..., outgoing_length=..., incoming_regex=..., incoming_length=...)`
turns any TCP socket into an FTE socket. The [`examples/`](examples/README.md)
directory has programmatic, chat, file-transfer and integration examples.

## Upgrading to 0.4.0

fteproxy 0.4.0 moves to libfte 0.4 (`fte.FTE`) and its wire format is **not
compatible with 0.3.x**. A 0.3 client and a 0.4 server (or the reverse) fail at
negotiation (the server logs a warning, the client times out), so upgrade both
endpoints together.

- **Key.** libfte 0.4 requires a 32-byte key. If you pass neither `--key` nor
  `--key-file`, fteproxy uses a built-in default key that is public and warns at
  startup. Generate one (`python3 -c "import secrets; print(secrets.token_hex(32))"`)
  and use the same key on both sides.
- **Record-layer mode.** New `--record-layer-mode` (`hybrid`, the default, or
  `format`). Both endpoints must use the same mode.
- **API renames.** `wrap_socket(outgoing_fixed_slice=, incoming_fixed_slice=)`
  are now `outgoing_length=` / `incoming_length=`; `fteproxy.defs.getFixedSlice`
  is `getLength`; the definitions JSON key `"fixed_slice"` is `"length"`. Code
  that used `fte.Encoder` directly must move to `fte.FTE` (see
  [libfte's README](https://github.com/kpdyer/libfte#readme)).
- **Formats.** Twenty low-capacity formats got longer covertexts (`binary`
  256 to 1032, `ip-address` and `timestamp` 64 to 312, and so on; see
  `fteproxy/defs/20260110.json`). Four patterns were rewritten for libfte
  0.4's stricter regex dialect (`\C` is now `.`; `manual-http-request` paths
  no longer admit a backslash). The default `manual-http-*` formats still use
  length 256 and carry 150 (request) and 192 (response) bytes per covertext.
- **Requires** `fte>=0.4.0,<0.5.0` and `cryptography>=42.0`.

See [SECURITY.md](SECURITY.md) for the security model, including what the
record layer does and does not authenticate.

## Testing

```bash
python -m pytest fteproxy/tests/ -v
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

Kevin P. Dyer (kpdyer@gmail.com)
