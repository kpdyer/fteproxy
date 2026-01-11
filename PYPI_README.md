# fteproxy

[![Tests](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml/badge.svg)](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml)
[![PyPI version](https://badge.fury.io/py/fteproxy.svg)](https://badge.fury.io/py/fteproxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**fteproxy** provides transport-layer protection to resist keyword filtering, censorship, and discriminatory routing policies using Format-Transforming Encryption (FTE).

## Installation

```bash
pip install fteproxy
```

## Quick Start

### Server

```bash
python3 -m fteproxy --mode server --server_ip 0.0.0.0 --server_port 8080 --proxy_ip 127.0.0.1 --proxy_port 8081
```

### Client

```bash
python3 -m fteproxy --mode client --client_ip 127.0.0.1 --client_port 8079 --server_ip <server-ip> --server_port 8080
```

## How It Works

```
[Application] <-> [fteproxy client] <--FTE encoded--> [fteproxy server] <-> [Destination]
```

fteproxy encodes traffic to match user-specified regular expressions, making it appear as allowed traffic (e.g., HTTP) to network filters.

## Links

- **Documentation:** https://github.com/kpdyer/fteproxy
- **Homepage:** https://github.com/kpdyer/fteproxy
- **Publication:** [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf) (CCS 2013)

## License

MIT License
