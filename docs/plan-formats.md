# Format design history

The five-protocol plan was written on 2026-09-03 and is implemented in release
`20260903`. This document records the decisions; the maintained schema and
validation workflow are in [format authoring](format-authoring.md).

## Shipped result

| Base | Port hints | Mode hint | Wire lengths | Framing |
|---|---|---|---|---|
| `http` | 80, 8080, 8000 | hybrid | 200–700 | CRLF CRLF |
| `ftp` | 21 | format | 64–256 | CRLF |
| `smtp` | 25, 587 | format | 80–320 | CRLF |
| `sip` | 5060 | format | 300–800 | CRLF CRLF |
| `dns` | 53 | format | 90–272 | Two-byte message-length prefix |

Each base has request and response entries. HTTP is the fallback default.
The CLI uses port metadata only when neither `--format` nor the URI chooses
a format, and uses `mode_hint` after flag and URI mode overrides.
The fixed-length shape catalog remains available as `20260110`.

The selected formats model visible message structure. They do not implement
the protocols' application state machines. Random field values, biased message
types, and independent requests and responses remain detectable.
Claims about network prevalence or which formats evade particular deployments
need separate measurements.

## Implementation phases

| Phase | Result |
|---|---|
| F0 | Schema metadata, capacity checks, `defs-check`, realism harness |
| F1–F5 | HTTP, FTP, SMTP, SIP, and DNS fragments with protocol-specific tests |
| F6 | Fragments assembled into the default `20260903` release |
| F7 | Terminator framing and variable lengths for the four text formats |
| F7b | DNS prefix moved out of its regex, enabling variable wire lengths |

The phase labels are historical.

## Decisions that still matter

**Sample through the record layer.** Bare libfte encryption of short messages
can produce systematic low-rank prefixes. fteproxy pads plaintext to capacity
before encryption. The realism harness uses this same path; its checks measure
message structure and simple output statistics, not traffic indistinguishability.

**Check capacity at the right length.** The 128-byte cipher-plaintext floor
applies at the handshake's maximum length. Each shorter session-record length
must still carry the seal, a type byte, and at least one payload byte.
Custom long base names also need an explicit hello-fit check.

**Choose a length before ranking.** Variable format-mode records use up to
eight discrete lengths, derived identically by both peers. The chooser favors
shorter fitting frames for small writes and longer frames for queued bulk data.
This removes a single repeated size, but does not reproduce a protocol's
length distribution.

**Prove terminator uniqueness.** The current validator traverses a regex
DFA/KMP product to prove the terminator occurs exactly once at the end of every
accepted string, including overlapping matches and repetitions. It replaces
the earlier character-class and literal-skeleton heuristic.

**Keep external framing outside the regex.** DNS's two-byte TCP prefix
announces the message length and is added by `LengthPrefixed`.
The regex describes the message behind it. The same pattern therefore serves
all eight wire lengths.

**Use short hybrid headers.** Handshakes remain at maximum length.
Hybrid headers use the shortest allowed length whose header regex holds the
16-byte sealed body-length field. HTTP's headers are 200 bytes; the early
plan's maximum-length hybrid headers are superseded.

**Give HTTP ciphertext valid body framing.** Handshakes and format-mode
records use the base zero-body grammar. Hybrid data uses separate POST and
response grammars with `Transfer-Encoding: chunked`, then one ciphertext
chunk and a terminal zero chunk. This corrected an earlier invalid HTTP layout
and changed the development wire format. It still requires a direct TCP path
that preserves bytes and does not correlate requests with responses.

## Maintaining the release

`fteproxy/defs/parts/<protocol>.json` is the source for each pair.
Reassemble `fteproxy/defs/20260903.json` after editing a fragment and run
`test_release_assembly.py`, `defs-check`, and the protocol tests.
See [the authoring workflow](format-authoring.md#assemble-and-validate).
