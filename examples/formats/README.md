# Direct libfte format examples

These scripts use libfte locally, without sockets or fteproxy session records.
Run them from `examples/formats` after installing the checkout:

```bash
python3 comparison_demo.py
python3 words_demo.py
python3 http_demo.py
```

| Script | Output |
| --- | --- |
| `comparison_demo.py` | One message in nine 1024-byte shapes: letters, digits, hex, words, binary, base64 characters, URL paths, and CSV |
| `words_demo.py` | 256 bytes of space-separated lowercase letter sequences |
| `http_demo.py` | A 256-byte HTTP-like GET request shape |

Each script generates a 32-byte key, builds an `fte.RegexFormat`, encrypts a
message, and checks that decryption recovers it. The words are not natural
language. The simplified GET shape omits the Host header required by HTTP/1.1;
it is distinct from the proxy's current HTTP definitions.

## Reading the output

A fixed-length libfte covertext always has the requested byte length. With a
short, unpadded plaintext, it can start with long runs of low-ranked symbols,
such as `aaaa…` or `0000…`. The previews expose that unused capacity.

fteproxy adds a length/sequence seal and random padding before FTE encryption,
which removes that systematic prefix. Padding does not make generated text
semantically natural or uniformly sample every string in the regex language.

## Using formats in a tunnel

Run `fteproxy formats` for the installed default catalog, or
`fteproxy formats --defs 20260110` for the older shape catalog. Direct examples
define their own regexes; running one does not register it with the proxy.

Proxy formats use a base name such as `http`, with request and response entries
for the two directions. Both peers need the same definitions; the client chooses
the base and mode during the handshake. CLI mode hints and socket-API defaults
are described in the [examples guide](../README.md#tunnel-behavior).
See [format authoring](../../docs/format-authoring.md) to add a definition.
