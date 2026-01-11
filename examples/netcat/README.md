# FTE Netcat Demo

Demonstrates fteproxy relay mode with netcat for interactive testing.

## Architecture

```
[netcat client] --> [fteproxy client:8079] --FTE--> [fteproxy server:8080] --> [netcat server:8081]
```

All traffic between the fteproxy client and server is FTE-encoded to look like
HTTP traffic (or other formats depending on configuration).

## Quick Start

1. Run the demo script:
   ```bash
   ./demo.sh
   ```

2. In another terminal, connect with netcat:
   ```bash
   nc 127.0.0.1 8079
   ```

3. Type messages - they will appear in the first terminal.

## Ports

| Port | Service |
|------|---------|
| 8079 | fteproxy client (connect here) |
| 8080 | fteproxy server (FTE traffic) |
| 8081 | netcat server (plaintext) |

## Manual Setup

If you prefer to run each component separately:

```bash
# Terminal 1: Start fteproxy server
python -m fteproxy --mode server \
    --server_ip 127.0.0.1 --server_port 8080 \
    --proxy_ip 127.0.0.1 --proxy_port 8081

# Terminal 2: Start fteproxy client
python -m fteproxy --mode client \
    --client_ip 127.0.0.1 --client_port 8079 \
    --server_ip 127.0.0.1 --server_port 8080

# Terminal 3: Start netcat server
nc -l 8081

# Terminal 4: Connect with netcat client
nc 127.0.0.1 8079
```

## Notes

- The demo uses `python -m fteproxy` for portability
- Press Ctrl+C to stop the demo and clean up all processes
- Traffic on port 8080 is FTE-encoded; traffic on 8079 and 8081 is plaintext
