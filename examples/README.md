# fteproxy examples

These examples cover the CLI, the socket API, and direct libfte encoding.
Install the checkout first, from the repository root:

```bash
python3 -m pip install -e .
```

| Directory | Examples |
| --- | --- |
| [basic](basic/README.md) | CLI server and local forwarding, with pass-through shell wrappers |
| [netcat](netcat/README.md) | A local tunnel with automatic startup and cleanup |
| [chat](chat/README.md) | A scripted ten-round socket conversation |
| [programmatic](programmatic/README.md) | Echo sockets, file transfer, and direct encoding |
| [formats](formats/README.md) | Compare regex output from direct libfte calls |
| [integration](integration/README.md) | SSH, SOCKS5 browsing, netcat, and interactive chat |

## Tunnel behavior

The client chooses a destination through `-L` forwarding or the `-D` SOCKS5
listener. The server resolves and connects to it if its `--allow` policy permits.
The client/server hop is encrypted; use the application's own encryption when
needed beyond that hop.

The default definitions release is `20260903`: `http`, `ftp`, `smtp`, `sip`, and
`dns`. The CLI selects a format from an explicit option, URI hint, server port,
or the `http` fallback. Its mode comes from an explicit option, URI hint, format
hint, or the `hybrid` fallback. HTTP hints `hybrid`; the other shipped protocols
hint `format`.

In `format` mode, each typed record is encoded into covertexts. In `hybrid` mode,
each record has an FTE header and an authenticated ciphertext body; HTTP frames
that body as a complete chunked message. Regex compliance does not guarantee
normal protocol behavior or resistance to traffic analysis.

The socket examples explicitly select `http` and inherit the API's `hybrid`
default. The API does not apply CLI port or mode hints. Both peers need matching
definitions even though the client selects the format and mode in the handshake.

## Demo identities

The Python socket examples publish a fixed private key and bind their servers to
all IPv4 interfaces. Use them in a controlled demo environment. For actual use,
generate a private identity, distribute only its connection capability, and bind
the listener deliberately. See [security](../SECURITY.md).

CLI examples generate a private key on first start and save the connection URI
in `connection.txt`; `server` reports the path without printing the capability.
Use `--advertise HOST:PORT` for an endpoint reachable from another machine, then
copy `connection.txt` privately and use `client --connection-file FILE`.

See the [main guide](../README.md) for complete CLI options and
[format authoring](../docs/format-authoring.md) for custom proxy definitions.
