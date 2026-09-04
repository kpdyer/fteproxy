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
drives the format-mode `Encoder` and cuts the wire back into individual sealed
covertexts — by length, on the terminator, or on the length prefix, exactly as
that format's decoder frames it. Pass it the definitions entry
(`format_covertexts(spec, n=256)`) so it picks the right framing; passing
`regex, length` still works for a fixed-length format. What comes back is
always what went on the *wire*, framing included. Use it, and
`statistical_guard`, in every `test_format_<proto>.py`.

**What this can and cannot buy.** A sealed covertext is *structurally* a valid
message — correct verbs, headers, terminators — but its field *values* are
random within their character class (a 300-character random URL path, not
`/index.html`). Realistic value *content* is not reachable by uniform rank
sampling. A realistic *length distribution* is not either, though a
variable-length format (below) at least replaces one repeated size with a
spread of eight. State these limits honestly; do not imply more.

## The capacity floor: `>= 128`

Every format must carry the protocol-v1 client hello (about 75 bytes plus the
28-byte AE frame) in one covertext. Build the cipher and require
`max_plaintext_bytes >= fteproxy.defs.MIN_CAPACITY` (128). Raise `length` until
it does. `defs-check` and the load-time `check_capacities` both enforce this.

For a variable-length format the floor applies at `max_length`, because that is
the length the handshake seals at. The *shortest* length only has to carry one
data record — a type byte, the 12-byte seal, and at least one payload byte — and
`defs-check` enforces that separately, at every length in the set.

## Variable-length formats

A fixed-length format emits every covertext at exactly one length, which is a
fingerprint of its own: a length-distribution test separates it from real
traffic without reading a byte. A format avoids that by declaring a range and a
way to delimit one covertext from the next, instead of a `length`:

```json
"ftp-request": {
  "regex": "^((USER|PASS|CWD) [a-zA-Z0-9._@/-]+|PASV|QUIT)\r\n$",
  "min_length": 64,
  "max_length": 256,
  "terminator": "\r\n",
  ...
}
```

Then, in `format` mode, each record picks one of
`fteproxy.defs.spec_allowed_lengths(spec)` — eight lengths spread evenly across
the range, including both ends — and is sealed with a fixed-length cipher at
that length. Both ends derive the set from the same definitions entry, so
nothing about it is negotiated. The two handshake records and the server's
first-record scan stay at `max_length`: the server has to frame a client hello
before it can decrypt anything, so the hello's length cannot depend on its
contents, and the longest covertext is the one choice that always has room.

A `hybrid`-mode header is a fixed-length frame too, but it goes at
**`fteproxy.hybrid_header_length(spec)` — the shortest allowed length whose
cipher has room for a header**, not at `max_length`. A header carries four
bytes, the length of the raw body behind it, and nothing else
(`record_layer.HYBRID_HEADER_BYTES`, 16 bytes of plaintext once the seal's
length and sequence fields are counted). Ranking a covertext gets superlinearly
more expensive as it gets longer — sealing `http`'s header at 200 bytes instead
of 700 is roughly seven to eight times cheaper per record — and every hybrid
record pays it once, so sealing a four-byte header at the format's longest
length made the shipped default several times slower in bulk and in latency than
it needed to be, for nothing. The length is computed
from the definitions entry by that one function, so both ends reach the same
answer and the decoder's frame size follows from its own header cipher; nothing
about it is negotiated either. For a fixed-length format there is one allowed
length, so this *is* `max_length` and nothing changes. A format with no allowed
length that can hold a header cannot run in hybrid mode at all: `defs-check`
refuses it, and a session that asks for hybrid is refused with
`fteproxy.HybridUnsupportedError` rather than quietly framed some other way.

Those lengths are always lengths **on the wire**. For the two framings below
that is the same as the cipher's covertext length; for `length-prefix` framing
the cipher is built two bytes shorter and the prefix makes up the difference.
`fteproxy._spec_cipher(spec, wire_length, key)` is the one place that
subtraction happens, so every other caller just names a wire length.

Two rules make this work, and both are easy to get wrong.

### The length must be chosen per record, not left to libfte

`fte.RegexFormat` accepts a `min_length`/`max_length` pair and will happily rank
the whole range for you. **Do not use it for this.** The number of strings in a
language grows exponentially with length, so a uniformly random rank lands in
the longest length class almost every time: a 64–512 range emits ~512-byte
covertexts and the fingerprint survives, with nothing in the tests to show for
it. `fteproxy.record_layer.VariableLength.choose_length` therefore picks the
length itself, from the discrete set, before sealing — biased towards short
lengths when the payload fits in one record and long ones when more data is
queued, so a length histogram reflects what the connection is carrying.

The set is small (eight) because each length costs one compiled DFA. A
continuous range would cost one per byte.

### Framing kind 1: the terminator must be impossible anywhere but the end

The decoder frames the wire by reading up to the next terminator, so if the
format's *language* can produce that byte string anywhere else, a covertext gets
cut in half and the connection fails closed on traffic that was perfectly valid.
`fteproxy.defs.validate.check_terminator_uniqueness` proves it cannot, from the
pattern, with two conservative rules:

1. **No character class may admit a terminator byte.** For a CRLF terminator,
   no field may contain a CR or an LF at all. This is deliberately stronger than
   "no class admits both": it makes every terminator byte come from a literal,
   which is what makes rule 2 exhaustive.
2. **No *literal skeleton* may contain the terminator before its end.** A
   skeleton is one covertext with each character-class run collapsed to a
   single placeholder — the literals and their adjacencies, and nothing else.
   The check expands one skeleton per alternation branch and per
   present-or-absent optional atom, rather than concatenating the pattern's
   literals once, because a single concatenation both invents adjacencies that
   never occur and, worse, *misses* the adjacency between a branch's last
   character and whatever follows the group. A repetition is expanded to one
   and two copies, which exposes the junction where a repeated unit meets
   itself. A pattern that expands to more than 4096 skeletons is refused rather
   than passed: framing that cannot be proven is not framing.

`validate_format` also re-checks the property on sampled covertexts, which is
the net for the one gap the static check leaves — a terminator spanning three or
more copies of a repeated group.

This is why `http-response` ends at the header block's `\r\n\r\n` with
`Content-Length: 0` and has no body field: the body-absorbing
`[a-zA-Z0-9/+= \r\n-]*` it used to end with admitted CR and LF, so a covertext
could carry `\r\n\r\n` inside it. A response with no body (`302`, `304`, or a
`200` with `Content-Length: 0`) is valid HTTP, and the capacity the body carried
moved into the `Server`, `Content-Type`, `ETag` and `Set-Cookie` values.

### Framing kind 2: a length prefix, which is framing and not language

Some protocols already say how long each message is. DNS over TCP is the plain
case: RFC 1035 section 4.2.2 puts a two-byte big-endian length in front of every
message, and that is the whole framing layer.

`dns` originally spelled that prefix as a literal at the head of its regex
(`\u0001\u000e` — 270, for a fixed 272-byte covertext), and that is precisely
what kept it fixed-length through F7: a second covertext length needs a second
prefix, hence a second regex. F7b lifted the prefix out of the pattern:

> **A length prefix is framing, not language.** The regex describes the
> *message*; the record layer writes the prefix in front of it on send and
> frames on it on receive.

That is what a `length-prefix` format declares, and it needs no terminator:

```json
"dns-request": {
  "regex": "^[\u0000-\u00ff][\u0000-\u00ff]\u0001\u0000...\u0000\u0001$",
  "min_length": 90,
  "max_length": 272,
  "framing": "length-prefix",
  ...
}
```

How it works, end to end:

- **Encoder.** Choose a wire length `W` from `spec_allowed_lengths` (the same
  chooser and the same short bias as a terminator-framed format), seal the chunk
  with the fixed-length cipher at message length `W - 2` — padded to that
  length's capacity, per the seal-padding rule — and emit `prefix(W-2) ||
  covertext`. `record_layer.LengthPrefixed` wraps the cipher and does the last
  step, so `_seal`, the handshake and a `hybrid` header all keep working on a
  cipher whose `encrypt` produces exactly `W` bytes and whose
  `output_format.max_length` reports `W`.
- **Decoder.** Wait for two bytes; read `n`; require `W = n + 2` to be one of
  the allowed wire lengths and **fail the stream closed immediately** if it is
  not. A 65535-byte prefix is a protocol violation, not a large record still
  arriving, and treating it as the latter is how a decoder is talked into
  buffering on a stranger's say-so. Then wait for `n` more bytes, decrypt with
  the `(pattern, n)` cipher, and unseal at the current sequence number.
- **The buffer bound comes for free.** Terminator framing has to impose one,
  because a peer can simply never send a terminator; here every record announces
  its own size, so the buffer never holds more than one longest covertext
  without either producing a record or failing.
- **The invariants are the terminator path's**: the seal must unseal at the
  current `seq`, any authentication failure is fatal to the stream, and a
  covertext of an unlisted length is refused rather than reinterpreted.

The capacity floor is what sets `min_length` for this kind of format, and it can
bite hard. A DNS message's rank space is small — the header and the question
trailer are fixed bytes and the capacity lives in the QNAME — so a short
covertext is perfectly good DNS and useless as a record. The binding direction
is the *reply*, which spends 16 more fixed bytes than a query on its answer
record: it first holds a whole data record at 86 wire bytes, and `dns` sets
`min_length` to 90, just above that floor and an exact step of 26 below the
272-byte maximum. Below 86, `defs-check` refuses the entry rather than shipping
a length no record fits in.

Checking a `length-prefix` format is different in kind from checking a
terminator: there is nothing in the pattern to prove, because the prefix is not
in the pattern. `defs.validate` instead checks what the record layer *emits* —
per allowed wire length, that the prefix equals `W-2`, that the message behind
it fullmatches the regex, and that the wire length is one the format declared.
`check_terminator_uniqueness` does not apply and is not run.

## Mode suitability

The schema-v2 `mode_hint` records which record-layer mode a format is designed
for. The client's `--mode` still overrides it.

- **http → `hybrid`.** Hybrid framing formats only a fixed-length header per
  record and sends the body as raw authenticated bytes. That reads as an HTTP
  message with a body, which is exactly what HTTP looks like. Fast.
- **line protocols (ftp, smtp, sip) and the binary dns format → `format`.** A pure line protocol has
  no natural place for a raw high-entropy body, so every byte is transformed into
  the target format (about 1 MB/s, fine for interactive circumvention). Document
  that `hybrid` on a line protocol leaks a high-entropy tail.

## Schema v2 keys

Each entry keeps `regex` and `length` (a v1 entry with only those still loads;
every new key defaults so old files are unchanged). The optional keys:

| key | type | default | meaning |
|---|---|---|---|
| `min_length`, `max_length` | int / null | `null` | variable length: the ends of the covertext-length range, **on the wire** |
| `terminator` | str / null | `null` | variable length: what every covertext ends with, and only ends with |
| `framing` | `fixed` \| `terminator` \| `length-prefix` | inferred: `terminator` when a terminator is declared, else `fixed` | how one covertext is told from the next |
| `port` | list[int] | `[]` | ports this format defaults on |
| `role` | `request` \| `response` \| `line` | inferred from the name suffix | direction |
| `mode_hint` | `hybrid` \| `format` | `hybrid` | designed-for record-layer mode |
| `default` | bool | `false` | exactly one base marks itself the release default |
| `description` | str | `""` | one-line human description |

A format is fixed length (`length`) or variable length (`min_length`,
`max_length`, and a delimiter — a `terminator`, or `"framing":
"length-prefix"`), never both and never half of one: a partial declaration would
load as a fixed-length format and quietly emit one length again, so
`check_capacities` refuses it, as it refuses an entry that declares both
delimiters. `fteproxy.defs.getLength()` and `spec_length()` return `max_length`
for a variable format, which is what the fixed-frame paths use.

Example (one line in the JSON; wrapped here):

```json
"http-request": {
  "regex": "^(GET|POST) /...\r\n\r\n$",
  "min_length": 200,
  "max_length": 700,
  "terminator": "\r\n\r\n",
  "port": [80, 8080, 8000],
  "role": "request",
  "mode_hint": "hybrid",
  "default": true,
  "description": "HTTP/1.1 GET or POST request with common headers"
}
```

The length-prefix counterpart, where the delimiter is a `framing` key rather
than a terminator and the regex describes the message alone:

```json
"dns-request": {
  "regex": "^[\u0000-\u00ff][\u0000-\u00ff]\u0001\u0000...\u0000\u0001$",
  "min_length": 90,
  "max_length": 272,
  "framing": "length-prefix",
  "port": [53],
  "role": "request",
  "mode_hint": "format",
  "default": false,
  "description": "DNS over TCP query (RFC 1035 4.2.2) ..."
}
```

## The verified HTTP starting point

This compiles, holds 448 bytes of capacity at length 700 (50 at length 200),
parses with Python's HTTP request parser, and satisfies the terminator rules
above (one line in the JSON; shown wrapped):

```
^(GET|POST) /[a-zA-Z0-9/._?=&%-]* HTTP/1\.1\r\n
Host: [a-z0-9.-]+\r\n
User-Agent: Mozilla/5\.0 \([a-zA-Z0-9;: .()]+\)\r\n
Accept: [a-zA-Z0-9/*,;= .+-]+\r\n
Accept-Language: [a-z,;=0-9. -]+\r\n
\r\n$
```

The matching response is `HTTP/1\.1 (200 OK|302 Found|304 Not Modified|404 Not
Found)` with `Server`, `Content-Type`, `Content-Length: 0`, `ETag` and
`Set-Cookie`, ending at the header block. It carried a body-absorbing field
until F7; see the terminator rules for why that field had to go.

## The fragment-file convention (F1–F5)

Each protocol phase P in {http, ftp, smtp, sip, dns} writes exactly three new
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
in parallel without colliding. **F6** assembled the fragments in
`fteproxy/defs/parts/*.json` into `fteproxy/defs/20260903.json` and made it the
default release (`fteproxy.conf`'s `fteproxy.defs.release`, with
`fteproxy.default_format` and `fteproxy.cli.DEFAULT_FORMAT` now `http`).

`parts/` stays the per-protocol source of truth: edit the fragment, then
re-assemble the release from it. `fteproxy/tests/test_release_assembly.py`
fails if the two drift, so an edit that never reaches the shipped file is
caught rather than shipped.

```python
import json
merged = {}
for proto in ('http', 'ftp', 'smtp', 'sip', 'dns'):   # the shipped file's order
    merged.update(json.load(open('fteproxy/defs/parts/%s.json' % proto)))
with open('fteproxy/defs/20260903.json', 'w') as fh:
    json.dump(merged, fh, indent=4)
    fh.write('\n')
```

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
