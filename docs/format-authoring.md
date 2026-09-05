# Authoring an fteproxy format

A definitions release maps direction names such as `http-request` and
`http-response` to regexes, wire lengths, and metadata. The client names their
shared base (`http`) in its hello. A usable tunnel needs both directions in
the same release; `role: line` is metadata and does not create a missing pair.

Edit the protocol fragment in `fteproxy/defs/parts/<protocol>.json`, then
reassemble `fteproxy/defs/20260903.json`. The release-assembly test checks
that they agree. The earlier fixed-length shapes remain in `20260110.json`.

## Regex dialect

libfte 0.4 uses regex2dfa 0.2.x to compile byte languages. Use its supported
subset rather than assuming Python `re` syntax:

- Use literals, `.`, character classes, groups, alternation, `*`, `+`,
  and `?`.
- Use leading `^` and trailing `$` for consistent whole-message checks.
  The compiler ignores unescaped anchors, so do not put them inside a pattern.
- Expand brace quantifiers: write `xxx`, not `x{3}`.
- Spell out classes such as `[0-9]`, or use the compiler's ASCII `\d` and
  `\w` shorthands. Its `\s` covers only space, tab, CR, and LF.
- Do not use lookarounds, backreferences, or non-capturing groups.
- Do not use backslash escapes inside character classes. Use `[a-z.]`,
  not `[a-z\.]`; put a literal hyphen first or last.
- Do not use empty groups or empty alternatives.
- Pattern characters must fit in one byte (U+0000–U+00FF).

JSON escapes and regex escapes are separate. JSON `"\r\n"` becomes actual
CR/LF bytes; a literal regex dot is written `"\\."` in JSON.
Validate both compilation and generated messages: unsupported syntax can be
misinterpreted as literals rather than rejected.

## Schema

| Key | Default | Meaning |
|---|---|---|
| `regex` | Required | Base language for handshakes and format-mode records |
| `length` | Configured default, 256 | Fixed wire length; omit when declaring a range |
| `min_length`, `max_length` | Absent | Endpoints of a variable wire-length range |
| `terminator` | Absent | Non-empty byte string occurring only at a covertext's end |
| `framing` | `terminator` when a terminator is present, otherwise `fixed` | `fixed`, `terminator`, or `length-prefix` |
| `hybrid_regex` | `regex` | Header language for post-handshake hybrid records |
| `hybrid_framing` | `raw` | `raw` or `http-chunked`, surrounding the encrypted body |
| `port` | `[]` | Integer port hints for CLI format selection |
| `role` | Inferred from name suffix | `request`, `response`, or `line` |
| `mode_hint` | `hybrid` | Preferred CLI mode: `hybrid` or `format` |
| `default` | `false` | Marks a release default; use one base |
| `description` | Empty string | One-line description for `fteproxy formats` |

A range requires both endpoints and either a terminator or
`framing: length-prefix`. It cannot also declare `length` or fixed framing.
Fixed-length formats may use `fixed` or `length-prefix` framing, but not a
terminator.

This complete fragment defines an FTP-shaped request direction:

```json
{
  "ftp-request": {
    "regex": "^((USER|PASS|CWD) [a-zA-Z0-9._@/-]+|PASV|QUIT)\r\n$",
    "min_length": 64,
    "max_length": 256,
    "terminator": "\r\n",
    "port": [21],
    "role": "request",
    "mode_hint": "format",
    "description": "FTP control commands"
  }
}
```

A server also needs a compatible `ftp-response` entry; see the
[shipped fragment](../fteproxy/defs/parts/ftp.json).

## Capacity and length selection

`cipher.max_plaintext_bytes` already accounts for libfte's encryption
overhead. fteproxy adds a 12-byte seal (four-byte message length and eight-byte
sequence number), plus one record-type byte for session records.
A format-mode record therefore carries at most `capacity - 13` application
bytes.

The loader requires at least `MIN_CAPACITY = 128` plaintext bytes at the
handshake length. A client hello occupies `43 + len(base_name)` bytes
before the seal, and the server hello occupies 50. The floor covers the shipped
names, not every possible 255-byte name; a custom long name must fit too.

For variable formats, the handshake length is `max_length`.
`spec_allowed_lengths(spec)` derives up to eight evenly spaced lengths,
including both endpoints. Every allowed length must compile and have capacity
for at least one payload byte after the seal and type.

In format mode, `VariableLength.choose_length` chooses a length before
sealing with a cipher fixed at that length. If the queued payload fits in one
record, only lengths that can hold it are eligible, weighted toward shorter
ones. Otherwise all lengths are eligible, weighted toward longer ones.
Ranking across a whole range instead would heavily favor its largest language
classes. The chosen distribution is not a model of real protocol traffic.

Hybrid headers use `fteproxy.hybrid_header_length(spec)`: the shortest
allowed length whose `hybrid_regex` holds 16 plaintext bytes (12-byte seal
plus four-byte encrypted-body length). Both peers compute it from the same
definition. `defs-check` rejects a format with no such length, even when its
mode hint is `format`. Session setup checks both directions before accepting
hybrid mode. A separate hybrid regex must be checked independently of the
base regex's capacity.

All declared lengths include external framing. For a length-prefixed format
with wire length `W`, the underlying cipher produces `W - 2` message
bytes. `fteproxy._spec_cipher(spec, W, key)` applies that adjustment and
returns a wrapper whose encryption emits exactly `W` bytes.

## Record framing

### Terminator

The decoder ends a record at the first terminator, then checks its length
against the allowed set. A missing terminator beyond the maximum length or an
unlisted frame length fails the stream.

`check_terminator_uniqueness` proves that every string accepted by the regex
contains exactly one terminator, at the end. It traverses the product of the
regex's minimized DFA and a Knuth–Morris–Pratt matcher, tracking whether a
completed terminator has been followed by another byte. The proof handles
repetitions and overlapping matches and returns an unsafe witness on failure.

This is a proof over the whole regex language, not just declared lengths.
It does not use the older literal-skeleton or character-class heuristics.
Sampled covertexts are checked as an additional runtime validation.

### Length prefix

`framing: length-prefix` puts a two-byte big-endian message length before
the covertext. This is the layout used by
[DNS over TCP, RFC 1035 §4.2.2](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2.2).
The prefix is outside the regex; do not encode a fixed prefix in the pattern.

On receipt, a variable decoder requires `declared_length + 2` to be allowed
before waiting for the body. Invalid lengths fail immediately. The prefix
itself is not MACed; the receiver checks its consistency with the frame and
then authenticates the selected covertext.

Validation checks each sampled prefix, wire length, and regex match after
removing the prefix. No terminator proof is needed.

## Padding and realism

Evaluate wire realism through the record layer, not bare
`fte.FTE.encrypt(short_message)`. `_seal` pads plaintext to the cipher's
capacity before encryption, avoiding systematic low-rank prefixes caused by
short messages. This does not imply uniform sampling of every accepted string
or realistic field values.

The test helper `fteproxy.tests.realism.format_covertexts(spec, n=256)`
returns complete wire covertexts, including any prefix. It uses the same
framing as the decoder. The legacy `format_covertexts(regex, length, n=256)`
form works for fixed-length formats.

Each protocol should provide:

1. A fragment in `fteproxy/defs/parts/<protocol>.json`.
2. An independent `check(covertext: bytes) -> None` parser in
   `fteproxy/tests/realism/<protocol>.py`.
3. Tests in `fteproxy/tests/test_format_<protocol>.py` for capacity,
   round trips, regex membership, parser acceptance, and the harness's
   `statistical_guard`.

Parser acceptance and the statistical guard catch structural mistakes and
degenerate output. They do not validate request/response correspondence, field
plausibility, traffic timing, or resistance to a protocol-aware classifier.

## Mode suitability and HTTP

`mode_hint` is advisory. The CLI lets `--mode` or a URI hint override it;
the Python socket API uses its configured mode default unless given one.

HTTP is the shipped hybrid carrier. Its base regex emits complete zero-body
messages for handshakes and format mode. Its separate hybrid regex emits POST
requests and body-permitted responses with `Transfer-Encoding: chunked`.
Do not include `Content-Length` or body-forbidden response statuses such as
304 in that grammar.

For a non-empty encrypted body of `B` bytes, the wire suffix after the header is:

```text
hex(B) || CRLF || body || CRLF || "0" || CRLF || CRLF
```

This adds `len(format(B, "x")) + 9` bytes. The decoder derives the expected
framing from the authenticated body length and checks the exact bytes.
See [HTTP/1.1 chunked coding, RFC 9112 §7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1).

The other shipped formats use format mode. Forcing hybrid appends ciphertext
outside their modeled messages. DNS's prefix, in particular, does not account
for that extra body.

HTTP framing does not create real transactions or support rewriting proxies.
Both directions emit records independently, and the tunnel needs a direct TCP
path that preserves bytes. Document equivalent limitations for new carriers.

## Assemble and validate

Run from the repository root after installing `.[test]`.
Reassemble the current release after editing its fragments:

```python
import json
from pathlib import Path

merged = {}
for protocol in ("http", "ftp", "smtp", "sip", "dns"):
    path = Path("fteproxy/defs/parts") / f"{protocol}.json"
    merged.update(json.loads(path.read_text()))
Path("fteproxy/defs/20260903.json").write_text(
    json.dumps(merged, indent=4) + "\n"
)
```

Validate the packaged releases and run the format tests:

```bash
python3 -m fteproxy defs-check --defs 20260903
python3 -m fteproxy defs-check --defs 20260110
python3 -m pytest fteproxy/tests/test_format_*.py \
  fteproxy/tests/test_defs_schema.py fteproxy/tests/test_variable_length.py \
  fteproxy/tests/test_release_assembly.py
```

To validate a fragment independently:

```python
from fteproxy.defs.validate import validate_fragment

validate_fragment("fteproxy/defs/parts/http.json")
```

`defs-check` compiles all allowed lengths, checks capacity and framing,
and round-trips 32 sampled payloads per tested mode. It always tests format
mode and also tests hybrid when `mode_hint` is `hybrid`.
Protocol-specific parser tests are separate. Success exits 0 with a summary;
validation failure exits 1.
