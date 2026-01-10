# fteproxy

[![Tests](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml/badge.svg)](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/fteproxy.svg)](https://badge.fury.io/py/fteproxy)

* Homepage: https://fteproxy.org
* Source code: https://github.com/kpdyer/fteproxy
* Publication: https://kpdyer.com/publications/ccs2013-fte.pdf

## Overview

fteproxy provides transport-layer protection to resist keyword filtering, censorship and discriminatory routing policies.
Its job is to relay datastreams, such as web browsing traffic, by encoding the stream into messages that satisfy a user-specified regular expression.

fteproxy is powered by Format-Transforming Encryption [1] and was presented at CCS 2013.

[1] [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf), Kevin P. Dyer, Scott E. Coull, Thomas Ristenpart and Thomas Shrimpton

## Requirements

- Python 3.8 or higher
- [fte](https://pypi.python.org/pypi/fte) - Format-Transforming Encryption library

## Quick Start

Install fteproxy using pip:

```console
pip install fteproxy
```

## Running from Source

```bash
git clone https://github.com/kpdyer/fteproxy.git
cd fteproxy
pip install -r requirements.txt
pip install -e .
./bin/fteproxy
```

## Usage

### Architecture

fteproxy operates as a client-server proxy:

```
[Application] <-> [fteproxy client] <--FTE encoded--> [fteproxy server] <-> [Destination]
```

### Start the Server

On the server machine, start the fteproxy server:

```bash
./bin/fteproxy --mode server --server_ip 0.0.0.0 --server_port 8080 --proxy_ip 127.0.0.1 --proxy_port 8081
```

This listens for FTE-encoded connections on port 8080 and forwards decoded traffic to 127.0.0.1:8081.

### Start the Client

On the client machine, start the fteproxy client:

```bash
./bin/fteproxy --mode client --client_ip 127.0.0.1 --client_port 8079 --server_ip <server-ip> --server_port 8080
```

This listens for plaintext connections on port 8079 and forwards FTE-encoded traffic to the server.

### Command Line Options

```
--mode          Relay mode: client or server (default: client)
--client_ip     Client-side listening IP (default: 127.0.0.1)
--client_port   Client-side listening port (default: 8079)
--server_ip     Server-side listening IP (default: 127.0.0.1)
--server_port   Server-side listening port (default: 8080)
--proxy_ip      Forwarding-proxy listening IP (default: 127.0.0.1)
--proxy_port    Forwarding-proxy listening port (default: 8081)
--key           Cryptographic key, hex, must be exactly 64 characters
--quiet         Be completely silent
--version       Output the version of fteproxy
```

### Run Tests

```bash
python -m pytest fteproxy/tests/ -v
```

## Documentation

See: https://fteproxy.org/documentation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Kevin P. Dyer (kpdyer@gmail.com)
