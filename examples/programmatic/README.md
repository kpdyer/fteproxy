# Programmatic fteproxy Examples

These examples show how to use fteproxy's Python API directly in your applications.

## The API

One of `server_key=` and `server_id=` picks the role. The client also picks the
format and the record-layer mode; the server learns both from the client's
first record, so nothing has to be configured to match:

```python
import fteproxy

private, public = fteproxy.generate_server_key()

# server side
sock = fteproxy.wrap_socket(sock, server_key=private)

# client side
sock = fteproxy.wrap_socket(sock, server_id=public,
                            format="words", mode="hybrid")
```

`server_id` also accepts the 43-character base64url string that a connection
string carries, and `fteproxy.server_id(private)` recovers the public half of a
key you already have. Wrapped sockets are used like ordinary sockets
(`connect`, `bind`/`listen`/`accept`, `sendall`, `recv`), plus `close_write()`
for a half-close.

To relay for someone else rather than talk to them, a wrapped socket can carry
a destination: the client calls `sock.open((host, port))` -- which raises
`fteproxy.OpenRefused(status)` if the peer refuses -- and the server calls
`sock.wait_open()` to learn the `(host, port)` asked for and answers with
`sock.open_result(status)`.

## Examples

### 1. `simple_encoder.py`
Direct encoding/decoding with libfte, without sockets or fteproxy. Good for
understanding how FTE transforms data.

### 2. `echo_client.py` / `echo_server.py`
Basic echo server using `fteproxy.wrap_socket()`.

### 3. `format_demo.py`
Demonstrates different output formats (words, hex, base64, etc.).

### 4. `custom_format.py`
Shows how to define and use custom regex formats.

### 5. `file_transfer.py`
Simple file transfer example using FTE encoding.

## Running the Examples

```bash
# Install fteproxy first
pip install fteproxy

# Run simple encoder demo
python simple_encoder.py

# Run echo server/client (in separate terminals)
python echo_server.py
python echo_client.py

# See different output formats
python format_demo.py

# Create custom formats
python custom_format.py
```

These scripts share a hardcoded demo keypair so that any two of them agree
without exchanging anything. A real server generates its own with
`fteproxy keygen`, keeps `server.key` at mode 0600, and hands out only the
public half.
