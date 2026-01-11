# Integration Examples

These examples show how to use fteproxy with common tools and services.

## SSH Over FTE

Tunnel SSH connections through fteproxy so they look like HTTP traffic.

### Server Side

```bash
# Terminal 1: Start fteproxy server (forwards to local SSH)
fteproxy --mode server --server_port 8080 --proxy_ip 127.0.0.1 --proxy_port 22

# Make sure sshd is running on port 22
```

### Client Side

```bash
# Terminal 1: Start fteproxy client
fteproxy --mode client --client_port 8079 --server_ip <server-ip> --server_port 8080

# Terminal 2: Connect via SSH through fteproxy
ssh -p 8079 user@localhost
```

## HTTP Proxy Over FTE

Use fteproxy to tunnel an HTTP proxy.

### Server Side

```bash
# Start a simple HTTP proxy (e.g., tinyproxy) on port 8888
# Then start fteproxy to expose it:
fteproxy --mode server --server_port 8080 --proxy_port 8888
```

### Client Side

```bash
# Start fteproxy client
fteproxy --mode client --client_port 8079 --server_ip <server-ip> --server_port 8080

# Use curl with the proxy
curl -x socks5://localhost:8079 https://example.com
```

## Netcat File Transfer

Transfer files using netcat through FTE encoding.

### Receiver Side

```bash
# Terminal 1: Start fteproxy server
fteproxy --mode server --server_port 8080 --proxy_port 9999

# Terminal 2: Wait for file with netcat
nc -l 9999 > received_file.txt
```

### Sender Side

```bash
# Terminal 1: Start fteproxy client
fteproxy --mode client --client_port 8079 --server_ip <server-ip> --server_port 8080

# Terminal 2: Send file
cat myfile.txt | nc localhost 8079
```

## Custom Key

For additional security, use a custom encryption key:

```bash
# Generate a random 64-character hex key
KEY=$(openssl rand -hex 32)
echo "Using key: $KEY"

# Server
fteproxy --mode server --key $KEY --server_port 8080 --proxy_port 8081

# Client (use the SAME key)
fteproxy --mode client --key $KEY --server_ip <server-ip> --server_port 8080
```

## Chaining with socat

Use socat for more complex forwarding scenarios:

```bash
# Forward from a Unix socket through fteproxy
socat UNIX-LISTEN:/tmp/fte.sock,fork TCP:localhost:8079
```
