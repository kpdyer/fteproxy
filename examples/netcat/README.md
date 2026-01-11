# Netcat Demo

A simple demonstration of fteproxy using netcat.

## Quick Start

```bash
# Terminal 1: Start the demo
./demo.sh

# Terminal 2: Send a message
echo "Hello, FTE!" | nc localhost 8079
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

## Ports

| Port | Purpose |
|------|---------|
| 8079 | FTE client listens here (you connect here) |
| 8080 | FTE server listens here (internal) |
| 8081 | Final destination (netcat listener) |

## Cleanup

Press `Ctrl+C` to stop. The script automatically cleans up all background processes.
