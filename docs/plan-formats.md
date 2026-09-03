# fteproxy formats: five cleartext protocols, done well

Status: proposal, 2026-09-03. Target: the uncut 1.0.0 line, on top of
`docs/plan-1.0.md` (already implemented on this branch). Ships a new dated
definitions release and makes it the default.

## Why these five, and why unencrypted

Format-Transforming Encryption earns its keep against a classifier that keys on
the *visible structure of a cleartext protocol*. If the target protocol is
itself encrypted (TLS, SSH), the honest move is to run the real protocol and
tunnel inside it: an observer expects a real handshake, and a hand-rolled
look-alike is weaker than the genuine article. FTE's edge is exactly the case
the real protocol cannot serve: sending arbitrary bytes shaped like a *plaintext*
application protocol, so a regex or keyword DPI rule matches and passes it.

So every shipped format is a protocol that is normally sent in the clear. Four are
line- or text-structured, where regex covertext is strongest; DNS over TCP is the
one binary format, carried because it is the highest-value circumvention channel:

| Format | Ports | Role split | Why |
|---|---|---|---|
| http | 80, 8080, 8000 | request / response | the canonical cleartext protocol; the default |
| ftp | 21 | command / reply | plaintext control channel, simple line grammar |
| smtp | 25, 587 | command / reply | plaintext commands, numeric replies |
| sip | 5060 | request / response | VoIP signaling: HTTP-like text, TCP-native, still voluminous in telecom |
| dns | 53 | query / response | DNS over TCP: the highest-value channel; binary wire format, the one non-text format |

**Revision 2026-09-03.** The first cut shipped imap and irc in the last two slots.
Both were dropped: imap is mail-family text with tagged commands and status replies,
so a classifier that models a mail-ish text protocol lumps it with smtp and it adds
a name rather than diversity; irc traffic has largely moved to TLS on 6697 and its
volume collapsed. They were replaced by sip (voice, a category nothing else covered)
and dns over TCP (the highest-value channel, and the one binary format). A broader
point drove the choice: TLS has absorbed most classic cleartext protocols, so the
set of still-common, still-cleartext, TCP-native protocols is short, and padding to
five drags in weak ones. UDP protocols (SNMP, native DNS, NTP) cannot be mimicked
over a TCP tunnel at all; a UDP datagram mode is under separate feasibility study.

## What "quality" can and cannot mean here (read before designing a format)

libfte draws a covertext by taking the AE ciphertext as an integer *rank* and
unranking it into the matching string at that rank. Two consequences shape every
design decision:

1. **Evaluate realism on SEALED covertexts, never on raw `FTE.encrypt` output.**
   The record layer's `_seal` pads the plaintext to the format's full capacity
   with random bytes *before* encrypting (`fteproxy/record_layer.py`), so a real
   record uses the whole rank space and fills variable fields with high-entropy
   format characters. A bare `FTE.encrypt(short_message)` does NOT pad, ranks
   low, and unranks into a degenerate covertext (a run of the field's lowest
   character). That degenerate string is an artifact of the harness, not of the
   product. The realism harness MUST produce covertexts through
   `fteproxy.record_layer.Encoder` (which seals), or it measures the wrong thing.

2. **Structure is achievable; value realism and length realism are bounded.**
   With seal-padding, a variable field is filled with random characters from its
   class, so a covertext is *structurally* a valid message (correct verbs,
   headers, terminators) but its field *values* are random within their class
   (a 300-character random URL path, not `/index.html`), and every covertext of
   a fixed-length format is the same length. So the honest quality ceiling for
   v1 is: parses as the real protocol, plausible per-field character classes,
   high-entropy fields. Realistic value *content* (a real User-Agent string) and
   a realistic *length distribution* are not reachable by uniform rank sampling;
   variable length (phase F7) narrows the length gap. State these limits in
   SECURITY.md rather than implying more.

## Hard constraints every format must meet

- **regex2dfa dialect (verified 2026-09-03).** No brace quantifiers `{n}`
  (write `xxx`, not `x{3}`); no `\d \D \s \S \w \W`; no backslash escapes
  *inside* `[...]` (a `\.` in a class is a literal backslash then dot, so write
  `[a-z.]`); no mid-pattern `^`/`$`; no empty groups or alternatives; patterns
  denote byte languages so every character must be <= U+00FF. Anchor with a
  leading `^` and trailing `$`. Alternation `(A|B|C)` and classes work.
- **Capacity floor.** Build the cipher and require
  `max_plaintext_bytes >= 128`, so the protocol-v1 client hello (about 75 bytes
  plus the 28-byte AE frame) fits in one covertext. Raise `length` until it does.
- **Verified starting point** (compiles, capacity 303 at length 512, parses with
  Python's HTTP parser):
  ```
  ^(GET|POST) /[a-zA-Z0-9/._?=&%-]* HTTP/1\.1\r\n
  Host: [a-z0-9.-]+\r\n
  User-Agent: Mozilla/5\.0 \([a-zA-Z0-9;: .()]+\)\r\n
  Accept: [a-zA-Z0-9/*,;= .+-]+\r\n
  Accept-Language: [a-z,;=0-9. -]+\r\n
  \r\n$
  ```
  (One line in the JSON; shown wrapped here.)
- **Mode suitability.** hybrid framing formats only the header and sends the body
  as raw authenticated bytes. That reads as an HTTP message with a body, so
  `http` sets `mode_hint: hybrid`. A pure line protocol (ftp/smtp/sip) or the binary dns format has
  no natural place for a raw high-entropy body, so those set `mode_hint: format`
  (every byte in the protocol; about 1 MB/s, fine for interactive circumvention)
  and the docs say hybrid on them leaks a high-entropy tail. The client's
  `--mode` still overrides.

## Definitions schema v2

Extend each entry in the release JSON, keeping `length` and `regex` working so
old files still load:

```json
"http-request": {
  "regex": "^(GET|POST) /...$",
  "length": 512,
  "min_length": null, "max_length": null,   // reserved for F7
  "port": [80, 8080, 8000],                  // ports this format defaults on
  "role": "request",                          // request | response | line
  "mode_hint": "hybrid",                      // hybrid | format
  "default": true,                            // exactly one base name true
  "description": "HTTP/1.1 GET or POST request with common headers"
}
```

## Execution model (for the agents)

```
        F0 foundation  (one agent, blocks everything)
                 |
   +------+------+------+------+------+     (five agents, parallel)
   F1     F2     F3     F4     F5
  http   ftp    smtp   sip    dns
   +------+------+------+------+------+
                 |
        F6 integration  (one agent)
                 |
        F7 variable length  (optional, one agent)
```

Run F0 alone. Then fan out F1 through F5 concurrently: they touch disjoint
entries in one new JSON file and a per-protocol validator/test file each, so
they do not collide. F6 assembles and wires. F7 is an independent stretch.

Shared operating rules for every agent (same as the CLI effort): work only in
this worktree on this branch; use `uv run python ...` and
`uv run --with pytest pytest` (no `pip`, and `python3` on PATH lacks the deps);
never run two test sessions at once (system/example tests bind fixed ports);
commit per phase with the trailer `Co-Authored-By: Claude Opus 4.8
<noreply@anthropic.com>`; do not push, tag, or open PRs; never commit
`uv.lock`/`.venv`; never bare `git stash`.

## Phases

### F0 — foundation (blocking)

- Schema v2 loader in `fteproxy/defs/__init__.py`: read the new keys, default
  the reserved ones, and keep `length`/`regex`-only entries valid.
- `fteproxy/defs/validate.py`: `validate_release(path)` builds a cipher for every
  format, asserts `max_plaintext_bytes >= 128`, round-trips N random payloads
  through `record_layer.Encoder`/`Decoder` in the format's `mode_hint` and (for
  http) in both modes, and asserts every sealed **format-mode** covertext matches
  the regex. Exposed as `fteproxy defs-check [--defs R]` and called from CI.
- Realism harness `fteproxy/tests/realism/`: one `check(covertext_bytes) -> None`
  per protocol that raises on a structurally invalid message. `http.py` MUST use
  an independent parser (`http.server.BaseHTTPRequestHandler`'s parser for
  requests, `email.parser` for the header block); the others are strict grammar
  checks plus a statistical guard (in format mode, over >= 2000 sealed
  covertexts: every one matches the regex, and no single character runs for more
  than a documented fraction of the covertext — catches a badly shaped regex
  whose only variable field is one long low-entropy run).
- New empty dated release file `fteproxy/defs/20260903.json` for F1–F5 to fill,
  and a copy of today's shape-format catalog preserved at
  `examples/defs/shapes-20260110.json` so `--defs` still reaches it.
- Extend `fteproxy formats` output with port, role, mode and description columns.
- `docs/format-authoring.md`: the dialect cheat-sheet, the seal-padding rule, the
  capacity floor, and the realism-harness contract, so F1–F5 need no re-derivation.
- Tests: schema loads old and new; `defs-check` passes on the shapes catalog and
  fails a deliberately too-small format; the harness rejects a malformed message.

Acceptance: `uv run python -m fteproxy defs-check --defs shapes-20260110` passes;
`pytest` green.

### F1–F5 — one cleartext protocol each (parallel)

Same shape for every protocol P in {http, ftp, smtp, sip, dns}:

- Write `P-request`/`P-response` entries in
  `fteproxy/defs/20260903.json`: regexes that model realistic message structure
  and cover several message types by alternation (methods/verbs, common headers
  or replies), realistic per-field character classes, `length` chosen so capacity
  >= 128 and the covertext is a plausible size for that protocol, plus `port`,
  `role`, `mode_hint`, `description`. Set `default: true` on http only.
- Pass the F0 realism harness for P, and add `fteproxy/tests/realism/P.py` if F0
  left it a stub. Add `fteproxy/tests/test_format_P.py`: compile, capacity floor,
  round-trip both roles through the record layer, every format-mode covertext
  matches and passes the realism check, and the negotiated first-record scan
  (from plan-1.0 PR2) still selects P from a mixed catalog.
- Document the format's design and its honest limitations in a short block in
  `docs/format-authoring.md` (value realism, length fingerprint, mode caveat).

Acceptance for each: `uv run python -m fteproxy defs-check --defs 20260903`
passes for P's entries; `pytest fteproxy/tests/test_format_P.py` green.

Per-protocol notes:
- **http (F1):** start from the verified regex above; add a matching response
  (`HTTP/1\.1 (200 OK|302 Found|404 Not Found)` with `Content-Type`,
  `Content-Length`, `Server`, then a body-absorbing field). `mode_hint: hybrid`.
- **ftp (F2):** requests `USER/PASS/CWD/TYPE/PASV/RETR/STOR/LIST/QUIT`; replies
  `220/230/331/250/150/226/550 <text>`. `mode_hint: format`.
- **smtp (F3):** requests `EHLO/MAIL FROM:<...>/RCPT TO:<...>/DATA/QUIT`; replies
  `220/250/354/550 <text>`, multiline `250-` continuations. `mode_hint: format`.
- **sip (F4):** requests `INVITE/REGISTER/ACK/BYE/OPTIONS sip:<user>@<host> SIP/2.0`
  with `Via`, `From`, `To`, `Call-ID`, `CSeq` and `Content-Length` headers, CRLF CRLF;
  responses `SIP/2.0 (100 Trying|180 Ringing|200 OK|404 Not Found)` with the same
  headers. HTTP-like text, so the http realism approach applies (independent header
  parsing). `mode_hint: format` (SIP bodies are SDP text, not raw). length ~512.
- **dns (F5):** DNS over TCP (RFC 1035 s4.2.2): a 2-byte big-endian length prefix,
  then a DNS message. Query: 12-byte header (ID, flags `0x0100` standard query with
  recursion desired, QDCOUNT=1, other counts 0), one question of length-prefixed
  `[a-z0-9-]` labels, QTYPE A or AAAA, QCLASS IN. Response: flags `0x8180`, QDCOUNT=1,
  ANCOUNT>=1, the question echoed, then an A record (name pointer `0xC00C`, type,
  class, TTL, RDLENGTH=4, four address bytes). This is BINARY: the regex is over raw
  bytes (byte-range classes), the JSON carries them as `\u00XX` escapes, and the
  capacity lives in the label bytes. realism/dns.py MUST use an independent DNS
  parser (validate the header counts, label lengths, the compression pointer and
  RDLENGTH consistency), not the format regex. A fixed length pads the QNAME into a
  long name, structurally valid but unusual; note it, and it is the strongest case
  for F7 variable length. `mode_hint: format`. length chosen so capacity >= 128.

### F6 — integration (after F1–F5)

- Make `20260903` the default release (the CLI default is "newest shipped").
- Port-to-format defaulting: when the client URI carries no `format` hint and no
  `--format` is given, choose the default format for the server port from the
  schema `port` lists (fall back to http). The server's `?format=` hint still
  wins; a `--format` that disagrees with the port still warns (plan-1.0 behavior).
- `fteproxy formats` shows the new catalog; retire the shape formats from the
  shipped release (kept in `examples/defs/`).
- Docs: README usage and options for the five formats and the port table;
  SECURITY.md gains the realism-limits paragraph from the section above and the
  per-mode leak note; PERFORMANCE.md notes format-mode throughput for the line
  protocols; examples pick a format that matches their port.
- Cross-format review: one pass confirming all five pass `defs-check`, the first
  record scan disambiguates them, and the hello fits each.

Acceptance: `uv run python -m fteproxy defs-check` (default release) passes;
a server on 8080 with a no-hint client selects http end to end; `pytest` green.

### F7 — variable-length covertexts (optional, independent)

The one change that removes the fixed-length fingerprint. Format mode only.

- Record layer: terminator-framed decoding. Each format ends every covertext in a
  terminator that appears nowhere else in its language (`\r\n\r\n` for http,
  `\r\n` for the line protocols); `Decoder.pop` in format mode splits the buffer
  on the terminator and decrypts each covertext, instead of reading a fixed
  `max_length` slice. Hybrid mode is unchanged and stays fixed-length.
- Convert the five formats to `min_length`/`max_length` ranges sized to each
  protocol's real message-length distribution; drop `length`.
- Tests: fragmented delivery across the terminator; a terminator byte pattern
  that also appears mid-message is impossible by construction, assert the regex
  forbids it; length distribution of sealed covertexts spans the range.

Acceptance: `pytest` green; a captured stream shows a spread of covertext lengths
rather than one.

## Decisions for the maintainer

- **D-F1** The five protocols above (vs a swap for POP3/SIP/NNTP/DNS).
  Recommended as written; DNS deferred as a separate binary-format effort.
- **D-F2** Ship line protocols as `mode_hint: format` (realistic, ~1 MB/s) rather
  than hybrid (fast, high-entropy tail). Recommended: yes; http stays hybrid.
- **D-F3** New dated release `20260903` as default, shape formats retired to
  `examples/defs/`. Recommended: yes.
- **D-F4** Do F7 (variable length) in this cycle or defer. Recommended: land
  F0–F6 first; F7 as a fast follow, since it is the only record-layer change.
