# Basic fteproxy Examples

This directory contains simple examples to get started with fteproxy.

`start_server.sh` and `start_client.sh` are one-line wrappers around
`python3 -m fteproxy server` and `python3 -m fteproxy client`; every argument
you give them is passed straight through.

## Quick Start

Four terminals on one machine.

### 1. Start the server

In terminal 1:
```bash
./start_server.sh --listen 127.0.0.1:8080 --allow 127.0.0.1:8081
```

The first start generates the server's keypair and prints the connection
string clients need, which it also writes to `connection.txt` in the state
directory. `--allow 127.0.0.1:8081` is what lets the server dial the service
in step 2: without any rule it refuses its own loopback addresses.

### 2. Start a destination service

In terminal 2:
```bash
# Simple echo server using netcat
nc -l 8081
```

### 3. Start the client

In terminal 3:
```bash
./start_client.sh -L 8079:127.0.0.1:8081
```

No connection string is needed here, because the client reads the
`connection.txt` the server just wrote. From another machine you would pass
the string the server printed as the first argument.

### 4. Send data

In terminal 4:
```bash
echo "Hello, World!" | nc localhost 8079
```

You should see "Hello, World!" appear in terminal 2!

## What's Happening

```
Your Traffic Flow:

  Terminal 4        Terminal 3           Terminal 1        Terminal 2
  +---------+      +-----------+        +-----------+     +---------+
  |  Your   |      | fteproxy  |        | fteproxy  |     | Actual  |
  |  App    |----->|  client   |=======>|  server   |---->| Service |
  |         |      |           |        |           |     |         |
  +---------+      +-----------+        +-----------+     +---------+
     :8079         -L 8079:127.0.0.1:8081   dials what      :8081
                   names the destination    the client
                   and encodes traffic      asked for
```

The server has no forward address of its own. The destination is chosen on the
client -- by `-L` here, or by whatever a SOCKS5 application asks for when you
use `-D` instead -- and travels inside the tunnel; the server dials it if
`--allow` permits.

Each record between the client and the server starts with a covertext shaped
like an HTTP request (client to server) or an HTTP response (server to client).
With the default `--mode hybrid` the rest of the record is raw authenticated
ciphertext; with `--mode format` the whole stream is in the format, much more
slowly. Both are the client's choice and travel in the handshake, so there is
nothing to keep in step on the server.

There is no shared secret to distribute. The server keeps an X25519 private key
in `server.key`, and the connection string carries only its public half. Treat
that string like a Tor bridge line: whoever holds it can connect, so keep it
secret, but it does not let its holder impersonate the server or read another
client's traffic.
