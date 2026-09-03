# Netcat Demo

A simple demonstration of fteproxy using netcat.

## Quick Start

```bash
# Terminal 1: Start the demo
./demo.sh

# Terminal 2: Send a message
echo "Hello, FTE!" | nc 127.0.0.1 8079
```

## What It Does

```
Traffic Flow:

  Terminal 2          Terminal 1 (demo.sh)
  +--------+    +------------+    +------------+    +---------+
  |  You   |--->| FTE Client |===>| FTE Server |--->| netcat  |
  |  (nc)  |    |   :8079    |    |   :8080    |    |  :8081  |
  +--------+    +------------+    +------------+    +---------+
                |            |    |            |
                | plaintext  |    | FTE encoded|    plaintext
```

The traffic between the FTE client and server is encoded to look like
random characters matching a regex pattern, making it difficult to identify
as proxy traffic.

The server has no forward address. `-L 8079:127.0.0.1:8081` on the client is
what names the destination, and it travels inside the tunnel; the server dials
it because `--allow 127.0.0.1:8081` permits it. With no `--allow` rule at all a
server refuses its own loopback addresses, so that rule is what publishes the
netcat listener.

The demo keeps its keypair in a throwaway `--state-dir`, generated on the first
start along with the connection string. The client is given the same directory
and reads the string back out of it, so neither side needs a shared secret or a
URI on its command line.

## Ports

| Port | Purpose |
|------|---------|
| 8079 | FTE client's `-L` forward (you connect here) |
| 8080 | FTE server listens here (internal) |
| 8081 | Final destination (netcat listener) |

## Cleanup

Press `Ctrl+C` to stop. The script kills every background process it started
and removes the temporary state directory.
