# fteproxy Examples

This directory contains examples demonstrating various uses of fteproxy.

## Directory Structure

```
examples/
├── basic/              # Getting started examples
│   ├── README.md
│   ├── start_server.sh
│   └── start_client.sh
│
├── chat/               # Simple FTE-powered echo client/server
│   ├── README
│   ├── client.py
│   └── server.py
│
├── formats/            # Different output format demonstrations
│   ├── README.md
│   ├── words_demo.py
│   ├── http_demo.py
│   └── comparison_demo.py
│
├── programmatic/       # Python API usage examples
│   ├── README.md
│   ├── simple_encoder.py
│   ├── echo_server.py
│   ├── echo_client.py
│   ├── format_demo.py
│   ├── custom_format.py
│   └── file_transfer.py
│
├── integration/        # Integration with other tools
│   ├── README.md
│   ├── ssh_tunnel.sh
│   ├── web_proxy.sh
│   └── secure_chat.py
│
└── netcat/             # Netcat-based demo
    ├── README.md
    └── demo.sh
```

## Quick Start

### 1. Basic Tunnel

```bash
# Terminal 1 - Server
fteproxy --mode server --server_port 8080 --proxy_port 8081

# Terminal 2 - Destination service
nc -l 8081

# Terminal 3 - Client  
fteproxy --mode client --server_ip 127.0.0.1 --server_port 8080

# Terminal 4 - Send data
echo "Hello" | nc localhost 8079
```

### 2. Python API

```python
import socket
import fteproxy

# Wrap a socket with FTE encoding
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock = fteproxy.wrap_socket(sock,
    outgoing_regex="^[a-z]+$",
    outgoing_fixed_slice=256,
    incoming_regex="^[A-Z]+$", 
    incoming_fixed_slice=256,
    negotiate=False)

sock.connect(("example.com", 8080))
sock.sendall(b"Hello, World!")
```

### 3. Direct Encoding

```python
import fte

encoder = fte.Encoder("^[a-z]+$", 256)
ciphertext = encoder.encode(b"Secret message")
plaintext, _ = encoder.decode(ciphertext)
```

## Available Formats

| Format | Looks Like | Example |
|--------|-----------|---------|
| `lowercase` | Random letters | `xkwqprmstyz` |
| `words` | Natural text | `hello world foo bar` |
| `hex` | Hexadecimal | `a1b2c3d4e5` |
| `http` | HTTP requests | `GET /page HTTP/1.1` |
| `base64` | Encoded data | `SGVsbG8gV29ybGQ` |

## Running Examples

```bash
# Make scripts executable
chmod +x examples/*/*.sh

# Run a demo
python examples/programmatic/format_demo.py
python examples/formats/comparison_demo.py
```

## Use Cases

1. **Bypass Traffic Filtering**: Make your traffic look like allowed protocols
2. **Privacy**: Prevent traffic analysis by disguising patterns
3. **Testing**: Validate firewall rules and network policies
4. **Research**: Experiment with traffic transformation techniques
