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
- [fte](https://pypi.python.org/pypi/fte) 0.1.0+
- [pyptlib](https://gitweb.torproject.org/pluggable-transports/pyptlib.git)
- [obfsproxy](https://gitweb.torproject.org/pluggable-transports/obfsproxy.git)
- [Twisted](https://twistedmatrix.com/)

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

Start the server:
```bash
./bin/fteproxy --mode server
```

Start the client:
```bash
./bin/fteproxy --mode client
```

Run tests:
```bash
python -m pytest fteproxy/tests/ -v
```

## Documentation

See: https://fteproxy.org/documentation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Kevin P. Dyer (kpdyer@gmail.com)
