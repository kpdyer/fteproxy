# FTE Output Format Examples

Three self-contained scripts that call libfte directly (no sockets, no proxy)
to show what the same data looks like in different covertext formats:

| Script | What it shows |
|--------|---------------|
| `comparison_demo.py` | One message in nine formats side by side (lowercase, uppercase, digits, hex, words, binary, base64, URL path, CSV) |
| `words_demo.py` | Messages as space-separated lowercase words |
| `http_demo.py` | Messages as `GET /... HTTP/1.1` requests |

```bash
python3 comparison_demo.py
python3 words_demo.py
python3 http_demo.py
```

Each script builds a cipher with `fte.FTE(output_format=fte.RegexFormat(pattern, length=N), key=key)`,
encrypts a message, checks that it decrypts, and prints the covertext.

## Reading the output

A raw libfte covertext is always exactly `length` bytes, and a short message
does not fill it, so the unused capacity comes out as a run of the format's
lowest-ranked character: `aaaa...` for letters, `0000...` for digits, `a a a`
for words, `GET /000...0<random tail> HTTP/1.1` for the HTTP format. That is
what these scripts print. It is expected, and it is not what fteproxy puts on
the wire: fteproxy's record layer random-pads every message to the format's
capacity before encryption, so a proxied covertext reads as random format text
end to end (`GET /0ECRjVCS...`).

To see a covertext without the run in a script like these, choose a `length`
close to what the message needs (libfte's README does this), or pad the
plaintext to `cipher.max_plaintext_bytes` yourself.

## Using a format with the proxy

Every built-in format has a `-request` (client to server) and a `-response`
(server to client) definition in `fteproxy/defs/20260110.json`. Pick them on
the client; the server negotiates the matching pair automatically:

```bash
python3 -m fteproxy --mode client --upstream-format words-request --downstream-format words-response ...
```

By default (`--record-layer-mode hybrid`) only a fixed-length header per record
is in the chosen format and the rest of the record is raw ciphertext. Add
`--record-layer-mode format` on both endpoints to put every byte in the format,
at much lower throughput. See the main README's "Upgrading to 0.4.0" section.

## Why different formats?

Different formats blend in with different traffic:

- **HTTP-like** (`http-simple`, `manual-http`): web traffic
- **Words / sentences**: natural text
- **Hex / base64**: encoded data, common in APIs
- **Digits, IP addresses, timestamps**: numeric fields

The full list is in [`../README.md`](../README.md#available-formats).
