# fteproxy

[![Tests](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml/badge.svg)](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/fteproxy.svg)](https://pypi.org/project/fteproxy/)

* Homepage: https://github.com/kpdyer/fteproxy
* Source code: https://github.com/kpdyer/fteproxy
* Publication: https://kpdyer.com/publications/ccs2013-fte.pdf

## Overview

fteproxy provides transport-layer protection to resist keyword filtering, censorship and discriminatory routing policies.
Its job is to relay datastreams, such as web browsing traffic, by encoding the stream into messages that satisfy a user-specified regular expression.

fteproxy is powered by Format-Transforming Encryption [1] and was presented at CCS 2013.

[1] [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf), Kevin P. Dyer, Scott E. Coull, Thomas Ristenpart and Thomas Shrimpton

## Requirements

- Python 3.8 or higher

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

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--mode` | Relay mode: client or server | client |
| `--client_ip` | Client-side listening IP | 127.0.0.1 |
| `--client_port` | Client-side listening port | 8079 |
| `--server_ip` | Server-side listening IP | 127.0.0.1 |
| `--server_port` | Server-side listening port | 8080 |
| `--proxy_ip` | Forwarding-proxy listening IP | 127.0.0.1 |
| `--proxy_port` | Forwarding-proxy listening port | 8081 |
| `--key` | Cryptographic key (64 hex characters) | (default key) |
| `--quiet` | Suppress output | false |
| `--version` | Show version and exit | |

## Testing

```bash
python -m pytest fteproxy/tests/ -v
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

Kevin P. Dyer (kpdyer@gmail.com)
