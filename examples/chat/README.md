# FTE Chat Example

A chat demo with a 10-round conversation between client and server.
All traffic is FTE-encoded to look like HTTP/1.1 requests and responses.

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
Format: http (HTTP requests out, HTTP responses back)
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
sock = fteproxy.wrap_socket(sock, server_id=DEMO_SERVER_ID, format="http")

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
| Client -> Server | "Hi there!" | `GET /Xq2p... HTTP/1.1` + headers (512 bytes) + raw ciphertext |
| Server -> Client | "Hello!" | `HTTP/1.1 200 OK` + headers (512 bytes) + raw ciphertext |

With fteproxy's default record-layer mode (`hybrid`), each record starts with a
512-byte covertext in the `http` format and carries the message itself as raw
authenticated ciphertext after it -- which is what an HTTP message with a body
looks like. To put every byte in the format, ask for `format` mode when
wrapping the client socket -- the server follows:

```python
sock = fteproxy.wrap_socket(sock, server_id=DEMO_SERVER_ID,
                            format="http", mode="format")
```

## Traffic Flow

```
+------------+                      +------------+
|   Client   |                      |   Server   |
+------------+                      +------------+
      |                                   |
      |  "Hi there!" as an HTTP request   |
      |  GET /Xq2pm9... HTTP/1.1 ...      |
      |---------------------------------->|
      |                                   |
      |  "Hello!" as an HTTP response     |
      |  HTTP/1.1 200 OK ...              |
      |<----------------------------------|
      |                                   |
     ...         (10 rounds)             ...
```

## Customization

Change `FORMAT` in `client.py` to any base name `fteproxy formats` lists, and
the wire format changes in both directions:

```python
FORMAT = "http"   # GET /... HTTP/1.1 with browser headers (the default)
FORMAT = "smtp"   # EHLO mail.example / 250-... command and reply lines
FORMAT = "sip"    # INVITE sip:...@... SIP/2.0 with Via/From/To/Call-ID
FORMAT = "dns"    # DNS over TCP: length prefix, header, question, A record
```

Pick the one whose port the traffic will be seen on -- that is what the command
line does for you when no `--format` is given. The abstract shape formats
(`words`, `hex`, `manual-http`, ...) live in release `20260110`; to use one,
select that release before wrapping the socket, on both ends:

```python
import fteproxy.conf
fteproxy.conf.setValue('fteproxy.defs.release', '20260110')
```

Only the client changes. The server is told nothing and follows.
