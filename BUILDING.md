# fteproxy Build Instructions

## Requirements

- Python 3.8 or higher
- GMP library (for cryptographic operations)

## Ubuntu/Debian

Install the following packages:

```bash
sudo apt-get update
sudo apt-get install python3-dev python3-pip libgmp-dev
pip install --upgrade fte pytest
```

Then, clone and build fteproxy:

```bash
git clone https://github.com/kpdyer/fteproxy.git
cd fteproxy
pip install -r requirements.txt
pip install -e .
```

Run tests:

```bash
python -m pytest fteproxy/tests/ -v
```

## macOS

Install Homebrew if you don't have it already:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Install the following packages:

```bash
brew install python gmp
pip install --upgrade fte pytest
```

Then, clone and build fteproxy:

```bash
git clone https://github.com/kpdyer/fteproxy.git
cd fteproxy
pip install -r requirements.txt
pip install -e .
```

Run tests:

```bash
python -m pytest fteproxy/tests/ -v
```

## Windows

Install Python 3.8+ from https://python.org/

Install the required packages:

```bash
pip install --upgrade fte pytest
```

Then, clone and build fteproxy:

```bash
git clone https://github.com/kpdyer/fteproxy.git
cd fteproxy
pip install -r requirements.txt
pip install -e .
```

Run tests:

```bash
python -m pytest fteproxy/tests/ -v
```

## Running fteproxy

Start the server:

```bash
./bin/fteproxy --mode server
```

Start the client:

```bash
./bin/fteproxy --mode client
```

For more options:

```bash
./bin/fteproxy --help
```
