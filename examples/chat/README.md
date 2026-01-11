# FTE Chat Example

A simple echo server/client demonstrating `fteproxy.wrap_socket()`.

## Traffic Flow

```
+------------+           +------------+           +------------+
|   Client   |  ------>  |  Network   |  ------>  |   Server   |
|            |           |            |           |            |
| "Hello!"   |           | 0101011... |           | "Hello!"   |
+------------+           +------------+           +------------+
     |                         |                        |
     |    plaintext           |  looks like binary     |   plaintext
```

## Quick Start

```bash
# Terminal 1: Start server
python3 server.py

# Terminal 2: Run client
python3 client.py
```

## Output

```
# Server terminal
Connected by ('127.0.0.1', 52431)

# Client terminal
Received b'Hello, world'
```

## How It Works

### Server (`server.py`)

```python
import socket
import fteproxy

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock = fteproxy.wrap_socket(sock,
    outgoing_regex='^(A|B)+$',     # Server sends As and Bs
    outgoing_fixed_slice=256,
    incoming_regex='^(0|1)+$',     # Client sends 0s and 1s
    incoming_fixed_slice=256,
    negotiate=False)

sock.bind(('', 50007))
sock.listen(1)
conn, addr = sock.accept()

data = conn.recv(1024)  # Automatically decoded from binary format
conn.sendall(data)      # Automatically encoded to A/B format
```

### Client (`client.py`)

```python
import socket
import fteproxy

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock = fteproxy.wrap_socket(sock,
    outgoing_regex='^(0|1)+$',     # Client sends 0s and 1s
    outgoing_fixed_slice=256,
    incoming_regex='^(A|B)+$',     # Server sends As and Bs
    incoming_fixed_slice=256,
    negotiate=False)

sock.connect(('127.0.0.1', 50007))
sock.sendall(b'Hello, world')  # Sent as: 01010110111010...
data = sock.recv(1024)         # Received as: ABBAABABBA... -> decoded
```

## Formats Used

| Direction | Regex | Looks Like |
|-----------|-------|------------|
| Client -> Server | `^(0|1)+$` | `010110101110101...` |
| Server -> Client | `^(A|B)+$` | `ABBAABABBAABAB...` |

## Key Concepts

- **`negotiate=False`**: Both sides know the formats in advance (no in-band negotiation)
- **Transparent encoding**: Just use `sendall()` and `recv()` normally
- **Bidirectional**: Different formats for each direction

## Customization

Try changing the regex patterns:

```python
# Look like words
outgoing_regex='^([a-z]+ )+[a-z]+$'

# Look like hex
outgoing_regex='^[0-9a-f]+$'

# Look like HTTP
outgoing_regex='^GET \\/[a-zA-Z0-9]+ HTTP\\/1\\.1\\r\\n\\r\\n$'
```
