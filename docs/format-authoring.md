# Authoring an fteproxy format

This is the reference for phases F1–F5 (the five cleartext protocols) so each
one can be written without re-deriving the rules. It covers the regex dialect,
the seal-padding rule that governs how realism is measured, the capacity floor,
which record-layer mode a protocol should use, the fragment-file convention that
keeps the five phases from colliding, and how to run the checks.

The foundation (schema v2 loader, `fteproxy/defs/validate.py`, the realism
harness in `fteproxy/tests/realism/`, and the `defs-check` CLI command) is in
place. A protocol phase writes only its own three files and touches no shared
file until F6 assembles the parts.

## The regex2dfa dialect (libfte 0.4, verified 2026-09-03)

libfte compiles each regex to a DFA with `regex2dfa`. Its dialect is narrower
than Python's `re`:

- **No brace quantifiers** `{n}` / `{n,m}`. Write `xxx`, not `x{3}`.
- **No perl classes**: `\d \D \s \S \w \W` are not supported. Spell classes out:
  `[0-9]`, `[a-zA-Z0-9]`.
- **No backslash escapes inside `[...]`.** A `\.` in a class is a literal
  backslash followed by a dot, not an escaped dot, so write `[a-z.]`, not
  `[a-z\.]`. To include `-` in a class put it first or last: `[a-z.-]`.
- **No mid-pattern `^` or `$`.** Anchor the whole pattern with a leading `^` and
  a trailing `$` and nothing else.
- **No empty groups or alternatives**: not `(A|)`, not `()`.
- **Byte languages**: every character must be `<= U+00FF`. The covertext is
  bytes; a pattern character stands for that byte.
- Alternation `(GET|POST)` and classes `[...]` work; escape a literal that is a
  regex metacharacter *outside* a class with a backslash (`HTTP/1\.1`, `\r\n`).

Anything outside this dialect either fails to compile (caught at load and by
`defs-check`) or, worse, compiles to a language you did not intend.

## The seal-padding rule (how realism MUST be measured)

libfte draws a covertext by taking the AE ciphertext as an integer *rank* and
unranking it into the string at that rank in the pattern's language. A short
message ranks low and unranks into a **degenerate** covertext — a long run of
the field's lowest character (`GET /000000… HTTP/1.1`). That is an artifact of
sampling, not of the product.

The record layer's `_seal` (`fteproxy/record_layer.py`) pads the plaintext to
the format's full capacity with random bytes *before* encrypting, so a real
record uses the whole rank space and fills every variable field with
high-entropy bytes from its class. Therefore:

> Evaluate realism only on **sealed** covertexts produced through
> `fteproxy.record_layer.Encoder` (in `format` mode), never on a bare
> `fte.FTE.encrypt(short_message)`.

The realism harness does this for you: `fteproxy.tests.realism.format_covertexts`
drives the format-mode `Encoder` and slices the wire into individual sealed
covertexts. Use it, and `statistical_guard`, in every `test_format_<proto>.py`.

**What this can and cannot buy.** A sealed covertext is *structurally* a valid
message — correct verbs, headers, terminators — but its field *values* are
random within their character class (a 300-character random URL path, not
`/index.html`), and every covertext of a fixed-length format is the same length.
Realistic value *content* and a realistic *length distribution* are not reachable
by uniform rank sampling; phase F7 (variable length) narrows the length gap.
State these limits honestly; do not imply more.

## The capacity floor: `>= 128`

Every format must carry the protocol-v1 client hello (about 75 bytes plus the
28-byte AE frame) in one covertext. Build the cipher and require
`max_plaintext_bytes >= fteproxy.defs.MIN_CAPACITY` (128). Raise `length` until
it does. `defs-check` and the load-time `check_capacities` both enforce this.

## Mode suitability

The schema-v2 `mode_hint` records which record-layer mode a format is designed
for. The client's `--mode` still overrides it.

- **http → `hybrid`.** Hybrid framing formats only a fixed-length header per
  record and sends the body as raw authenticated bytes. That reads as an HTTP
  message with a body, which is exactly what HTTP looks like. Fast.
- **line protocols (ftp, smtp, imap, irc) → `format`.** A pure line protocol has
  no natural place for a raw high-entropy body, so every byte is transformed into
  the target format (about 1 MB/s, fine for interactive circumvention). Document
  that `hybrid` on a line protocol leaks a high-entropy tail.

## Schema v2 keys

Each entry keeps `regex` and `length` (a v1 entry with only those still loads;
every new key defaults so old files are unchanged). The optional keys:

| key | type | default | meaning |
|---|---|---|---|
| `min_length`, `max_length` | int / null | `null` | reserved for F7 (variable length) |
| `port` | list[int] | `[]` | ports this format defaults on |
| `role` | `request` \| `response` \| `line` | inferred from the name suffix | direction |
| `mode_hint` | `hybrid` \| `format` | `hybrid` | designed-for record-layer mode |
| `default` | bool | `false` | exactly one base marks itself the release default |
| `description` | str | `""` | one-line human description |

Example (one line in the JSON; wrapped here):

```json
"http-request": {
  "regex": "^(GET|POST) /...$",
  "length": 512,
  "port": [80, 8080, 8000],
  "role": "request",
  "mode_hint": "hybrid",
  "default": true,
  "description": "HTTP/1.1 GET or POST request with common headers"
}
```

## The verified HTTP starting point

This compiles, holds 303 bytes of capacity at length 512, and parses with
Python's HTTP request parser (one line in the JSON; shown wrapped):

```
^(GET|POST) /[a-zA-Z0-9/._?=&%-]* HTTP/1\.1\r\n
Host: [a-z0-9.-]+\r\n
User-Agent: Mozilla/5\.0 \([a-zA-Z0-9;: .()]+\)\r\n
Accept: [a-zA-Z0-9/*,;= .+-]+\r\n
Accept-Language: [a-z,;=0-9. -]+\r\n
\r\n$
```

The matching response (F1) adds `HTTP/1\.1 (200 OK|302 Found|404 Not Found)`
with `Content-Type`, `Content-Length`, `Server`, then a body-absorbing field.

## The fragment-file convention (F1–F5)

Each protocol phase P in {http, ftp, smtp, imap, irc} writes exactly three new
files and touches no shared file:

1. `fteproxy/defs/parts/<P>.json` — the `<P>-request`/`<P>-response` (or
   `<P>-line`) entries, as a standalone JSON object of formats. Validate it in
   isolation with `fteproxy.defs.validate.validate_fragment(path)`.
2. `fteproxy/tests/realism/<P>.py` — exposes `check(covertext: bytes) -> None`,
   raising on a structurally invalid message. `http.py` MUST judge with an
   independent parser (`http.server.BaseHTTPRequestHandler` for the request
   line, `email.parser` for the header block); the line protocols use a strict
   grammar check.
3. `fteproxy/tests/test_format_<P>.py` — compile, capacity floor, round-trip
   both roles through the record layer, every format-mode covertext matches the
   regex and passes the realism `check`, and `statistical_guard` over the batch.

Because the five phases write disjoint entries and per-protocol files, they run
in parallel without colliding. **F6** assembles the fragments in
`fteproxy/defs/parts/*.json` into `fteproxy/defs/20260903.json` and makes it the
default release.

## Running the checks

Validate a whole release (searches `fteproxy/defs/` and then `examples/defs/`):

```
uv run python -m fteproxy defs-check --defs 20260903
uv run python -m fteproxy defs-check --defs shapes-20260110
```

It builds the cipher, checks the capacity floor, round-trips random payloads
through the record layer in the format's mode (both modes when `hybrid`), and
confirms every format-mode covertext matches the regex. Exit 0 on success with a
per-format capacity summary, exit 1 with the failures otherwise.

Run one protocol's tests:

```
uv run --with pytest pytest fteproxy/tests/test_format_<P>.py
```

Validate a fragment before F6 assembles it (from Python):

```python
import fteproxy.defs.validate as v
v.validate_fragment('fteproxy/defs/parts/http.json')
```

List a release with the schema-v2 columns:

```
uv run python -m fteproxy formats --defs 20260903
```
