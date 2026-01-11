# fteproxy Examples

This directory contains examples demonstrating different ways to use fteproxy.

## Examples

### chat/

A simple echo client/server using `fteproxy.wrap_socket()` for programmatic FTE encryption.

- **client.py** - Connects to server and sends a message
- **server.py** - Echoes received messages back to client

Key concept: Uses `negotiate=False` for symmetric client/server communication where both sides know the formats.

### netcat/

Demonstrates fteproxy relay mode with netcat for interactive testing.

- **demo.sh** - Starts fteproxy client, server, and netcat in one script

Shows the full relay architecture: application -> fteproxy client -> fteproxy server -> destination.

## Getting Started

1. Install fteproxy:
   ```bash
   pip install fteproxy
   ```

2. Choose an example and follow its README for instructions.

## Use Cases

| Example | Use Case |
|---------|----------|
| chat | Programmatic FTE in Python applications |
| netcat | Interactive testing and relay mode demonstration |

## More Information

- [fteproxy Documentation](https://github.com/kpdyer/fteproxy)
- [FTE Paper (CCS 2013)](https://kpdyer.com/publications/ccs2013-fte.pdf)
