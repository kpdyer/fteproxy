# Basic fteproxy Examples

This directory contains simple examples to get started with fteproxy.

## Quick Start

### 1. Start the server

In terminal 1:
```bash
python -m fteproxy --mode server --server_port 8080 --proxy_port 8081
```

### 2. Start a destination service

In terminal 2:
```bash
# Simple echo server using netcat
nc -l -k 8081
```

### 3. Start the client

In terminal 3:
```bash
python -m fteproxy --mode client --client_port 8079 --server_ip 127.0.0.1 --server_port 8080
```

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
     :8079           Encodes              Decodes           :8081
                     traffic as           back to
                     HTTP-like            plaintext
                     patterns
```

The traffic between the fteproxy client and server looks like HTTP requests/responses,
making it difficult for network monitors to identify as proxy traffic.
