# Scripted chat example

This socket demo exchanges ten predefined messages and replies. From
`examples/chat`, run these in separate terminals:

```bash
python3 server.py
```

```bash
python3 client.py
```

The server binds all IPv4 interfaces on port `50007`; the client connects to
`127.0.0.1`. Both should finish with `[OK] All 10 rounds completed successfully`.
They share a published demo identity; see [demo identity precautions](../README.md#demo-identities).

## Configuration and wire format

The client sets `format="http"` and inherits the socket API's `hybrid` mode.
The server learns these choices from the handshake and uses its own matching
definitions release.

For the current `20260903` definitions, session records use a 200-byte POST
request or HTTP response header followed by an authenticated encrypted body in
HTTP chunk framing. Handshake covertexts use the 700-byte base HTTP format.
These generated messages do not implement a browser or a full HTTP conversation.

To encode the payload into covertexts too, pass `mode="format"` in the client's
`wrap_socket` call. To try another base name, use `fteproxy formats` to list it
and pass the desired mode explicitly: the socket API does not use format hints.
Legacy shapes such as `words` require `defs="20260110"` on both peers.

The scripts exchange small messages in turn. General applications must add
message framing: `sendall` and `recv` boundaries need not match. See the
[socket API notes](../programmatic/README.md#socket-api).
