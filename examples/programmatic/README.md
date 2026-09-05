# Python API examples

Run these from `examples/programmatic` after installing the checkout.

| Script | Purpose |
| --- | --- |
| `simple_encoder.py` | Encode and decode with libfte, without sockets |
| `echo_server.py`, `echo_client.py` | Exchange bytes through wrapped TCP sockets on port 50007 |
| `format_demo.py` | Compare ten locally defined regex shapes |
| `custom_format.py` | Try DNA letters, `o`/`x` patterns, filenames, and hex strings |
| `file_transfer.py` | Transfer one file on port 50008; no arguments runs a self-test |

```bash
python3 simple_encoder.py
python3 format_demo.py
python3 custom_format.py
python3 file_transfer.py
```

For the echo demo, run `python3 echo_server.py` and `python3 echo_client.py` in
separate terminals. It shares port 50007 with the scripted chat demo, so run
only one pair at a time.

The socket examples use a published private key and bind all IPv4 interfaces.
Use them only as demos; see [demo identities](../README.md#demo-identities).

## Socket API

A server holds an X25519 private key. A client needs its matching public
connection capability. Generate a pair with `fteproxy.generate_server_key()`
or provision persistent state with `fteproxy keygen`.

```python
import socket
import fteproxy

private, public = fteproxy.generate_server_key()
server_socket = fteproxy.wrap_socket(
    socket.socket(), server_key=private, defs="20260903")
client_socket = fteproxy.wrap_socket(
    socket.socket(), server_id=public, defs="20260903",
    format="http", mode="hybrid")
```

This constructs two sockets; the server still needs `bind`, `listen`, and
`accept`, and the client needs `connect`. Client `connect` completes the
handshake. When wrapping an already-connected socket, call `handshake` or let
first I/O trigger it. The server accepts the client's format/mode choice from
its configured definitions release. Both peers must have matching definitions.

Keys accept 32 raw bytes or canonical 43-character base64url text.
`fteproxy.server_id(private)` derives the public capability. API defaults are
`http`, `hybrid`, and release `20260903`; unlike the CLI, the API does not infer
a format from the port or apply `mode_hint`.

The wrapper supports one reader and one writer. Applications must frame their
own messages: one `sendall` need not correspond to one `recv`, and `recv(n)` may
return more than `n` decoded bytes. `sendall` returns a byte count. Use
`close_write()` to send logical EOF and then stop sending data; `shutdown()`
acts on the raw socket.

For destination relaying, the client calls `open((host, port))`. The server
calls `wait_open()`, applies its destination policy, and answers with
`open_result(status)`. A refusal raises `fteproxy.OpenRefused` on the client.
The CLI relay implements this policy and dialing; wrapping a socket alone
does not provide them.

## File transfer

For a manual transfer, start the receiver in a disposable output directory and
send a file from another terminal:

```bash
python3 file_transfer.py receive
```

```bash
python3 file_transfer.py send myfile.txt 127.0.0.1
```

The receiver writes the supplied filename in its current directory and reports
a truncated SHA-256 check. This teaching example buffers the whole file, trusts
the peer's filename and size, and can overwrite existing files. Use a trusted
demo peer and disposable files. The sender's success message means its send
completed; it does not confirm that the receiver saved the file.

For direct libfte output and padding behavior, see the
[format examples](../formats/README.md).
