# FTE Chat Example

A chat demo with a 10-round conversation between client and server.
All traffic is FTE-encoded to look like binary (0s and 1s).

## Quick Start

```bash
# Terminal 1: Start server
python3 server.py

# Terminal 2: Run client
python3 client.py
```

## Sample Output

**Server:**
```
FTE Chat Server
==================================================
Listening on port 50007
Format and mode: whatever the client asks for
==================================================

Waiting for client...
Client connected from ('127.0.0.1', 52431)

[Round 1/10]
  Client: Hi there! How are you?
  Server: Hello! Welcome to the FTE chat server.

[Round 2/10]
  Client: What does FTE stand for?
  Server: I'm doing great, thanks for asking!

...
```

**Client:**
```
FTE Chat Client
==================================================
Connecting to 127.0.0.1:50007
Format: binary (0s and 1s in both directions)
==================================================

Connected!

[Round 1/10]
  Client: Hi there! How are you?
  Server: Hello! Welcome to the FTE chat server.

...
```

## How The Two Sides Are Configured

The client makes every choice and the server follows. All the client holds is
the server-id -- the public half of the server's keypair, which is what a
connection string carries:

```python
# client.py
sock = fteproxy.wrap_socket(sock, server_id=DEMO_SERVER_ID, format="binary")

# server.py -- no format, no mode, no shared key
sock = fteproxy.wrap_socket(sock, server_key=DEMO_SERVER_KEY)
```

The server learns the format and the record-layer mode from the client's first
record. A real server generates its keypair with `fteproxy keygen` and hands
out only the public half; these scripts hardcode a demo keypair so they agree
without exchanging anything.

## What's On The Wire

Even though the conversation looks normal, the actual network traffic is encoded:

| Direction | What You See | What's On The Wire |
|-----------|-------------|-------------------|
| Client -> Server | "Hi there!" | `0101101011101010110...` (1320 bytes) + raw ciphertext |
| Server -> Client | "Hello!" | `1101001011010110100...` (1320 bytes) + raw ciphertext |

With fteproxy's default record-layer mode (`hybrid`), each record starts with a
1320-byte covertext in the `binary` format and carries the message itself as
raw authenticated ciphertext after it. To make the whole stream binary, ask for
`format` mode when wrapping the client socket -- the server follows:

```python
sock = fteproxy.wrap_socket(sock, server_id=DEMO_SERVER_ID,
                            format="binary", mode="format")
```

## Traffic Flow

```
+------------+                      +------------+
|   Client   |                      |   Server   |
+------------+                      +------------+
      |                                   |
      |  "Hi there!" encoded as binary    |
      |  010110101110101011010110...      |
      |---------------------------------->|
      |                                   |
      |  "Hello!" encoded as binary       |
      |  110100101101011010011010...      |
      |<----------------------------------|
      |                                   |
     ...         (10 rounds)             ...
```

## Customization

Change `FORMAT` in `client.py` to any base name `fteproxy formats` lists, and
the wire format changes in both directions:

```python
FORMAT = "words"        # a a a xkq mfj ...
FORMAT = "hex"          # a1b2c3d4e5f6 ...
FORMAT = "manual-http"  # GET /... HTTP/1.1
```

Only the client changes. The server is told nothing and follows.
