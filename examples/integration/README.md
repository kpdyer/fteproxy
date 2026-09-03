# Integration Examples

These examples show how to use fteproxy with common tools and services.

The server never has a forward address of its own. It decides *what it is
willing to dial* with `--allow`; the client decides *where to go*, with `-L`
for one fixed destination or `-D` for a SOCKS5 listener that takes the
destination from the application.

## SSH Over FTE

Tunnel SSH connections through fteproxy so they look like HTTP traffic.

### Server Side

```bash
# Publish the local sshd. Without an --allow rule the server refuses its own
# loopback addresses, so this rule is what makes 127.0.0.1:22 reachable.
python3 -m fteproxy server --allow 127.0.0.1:22

# Make sure sshd is running on port 22
```

It prints a connection string. Copy that to the client.

### Client Side

```bash
# Terminal 1: Start fteproxy client
python3 -m fteproxy client 'fte://<server-id>@<server-ip>:8080' -L 2222:127.0.0.1:22

# Terminal 2: Connect via SSH through fteproxy
ssh -p 2222 user@localhost
```

`127.0.0.1:22` in the `-L` is resolved by the *server*, so it means the
server's own sshd.

## Web Browsing Over FTE

SOCKS5 is built in, so there is nothing to install on the server.

### Server Side

```bash
# Reach the public internet, but not this host's loopback or link-local
# addresses:
python3 -m fteproxy server

# Or reach everything, loopback included:
python3 -m fteproxy server --allow any
```

### Client Side

```bash
# Start fteproxy client with a SOCKS5 listener
python3 -m fteproxy client 'fte://<server-id>@<server-ip>:8080' -D 1080

# Use curl
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

Or point a browser at a SOCKS5 proxy on `127.0.0.1:1080`. Use
`--socks5-hostname` (and the browser's "proxy DNS when using SOCKS" setting)
so names are resolved by the server rather than leaking around the tunnel.

## Netcat File Transfer

Transfer files using netcat through FTE encoding.

### Receiver Side

```bash
# Terminal 1: Start fteproxy server, publishing the port netcat will use
python3 -m fteproxy server --allow 127.0.0.1:9999

# Terminal 2: Wait for file with netcat
nc -l 9999 > received_file.txt
```

### Sender Side

```bash
# Terminal 1: Start fteproxy client
python3 -m fteproxy client 'fte://<server-id>@<server-ip>:8080' -L 8079:127.0.0.1:9999

# Terminal 2: Send file
cat myfile.txt | nc localhost 8079
```

## Keys and the connection string

There is no shared secret to distribute. On its first start the server
generates an X25519 keypair in its state directory (`~/.local/state/fteproxy`
by default): `server.key` holds the private half at mode 0600, and
`connection.txt` holds the string clients need.

```bash
# Provision a key and print the string without starting a server
python3 -m fteproxy keygen --advertise vpn.example.com:8080
```

Without `--advertise` the string carries a literal `<server-ip>` placeholder
for you to substitute.

The connection string carries only the public half, so treat it like a Tor
bridge line: whoever holds it can connect, and its secrecy is what stops an
active prober from confirming your server is running fteproxy. It does not let
its holder impersonate the server or read another client's traffic.

On a single host you can skip it entirely -- the client reads `connection.txt`
from the same state directory:

```bash
python3 -m fteproxy server --allow 127.0.0.1:8081 &
python3 -m fteproxy client -L 8079:127.0.0.1:8081
```

## Chaining with socat

Use socat for more complex forwarding scenarios:

```bash
# Forward from a Unix socket through fteproxy
socat UNIX-LISTEN:/tmp/fte.sock,fork TCP:localhost:8079
```
