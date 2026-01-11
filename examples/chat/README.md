# FTE Chat Example

A chat demo with a 10-round conversation between client and server.
All traffic is FTE-encoded to look like binary or letters.

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
Client->Server format: binary (0s and 1s)
Server->Client format: letters (As and Bs)
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
Client->Server format: binary (0s and 1s)
Server->Client format: letters (As and Bs)
==================================================

Connected!

[Round 1/10]
  Client: Hi there! How are you?
  Server: Hello! Welcome to the FTE chat server.

...
```

## What's On The Wire

Even though the conversation looks normal, the actual network traffic is encoded:

| Direction | What You See | What's On The Wire |
|-----------|-------------|-------------------|
| Client -> Server | "Hi there!" | `0101101011101010110...` |
| Server -> Client | "Hello!" | `ABBAABABBAABBABA...` |

## Traffic Flow

```
+------------+                      +------------+
|   Client   |                      |   Server   |
+------------+                      +------------+
      |                                   |
      |  "Hi there!" encoded as binary    |
      |  010110101110101011010110...       |
      |---------------------------------->|
      |                                   |
      |  "Hello!" encoded as A/B letters  |
      |  ABBAABABBAABBABABAAB...           |
      |<----------------------------------|
      |                                   |
     ...         (10 rounds)             ...
```

## Formats Used

| Direction | Regex | Looks Like |
|-----------|-------|------------|
| Client -> Server | `^(0|1)+$` | `010110101110101...` |
| Server -> Client | `^(A|B)+$` | `ABBAABABBAABAB...` |

## Customization

Edit the regex patterns in both files to change the wire format:

```python
# Look like lowercase words
CLIENT_TO_SERVER = '^([a-z]+ )+[a-z]+$'
SERVER_TO_CLIENT = '^([A-Z]+ )+[A-Z]+$'

# Look like hex
CLIENT_TO_SERVER = '^[0-9a-f]+$'
SERVER_TO_CLIENT = '^[0-9A-F]+$'
```

Both client and server must use matching formats!
