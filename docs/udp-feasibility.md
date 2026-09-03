# fteproxy over UDP: a feasibility study

Status: study, 2026-09-03. No code change is proposed here and none was made.
Written against the 1.0.0 line as implemented on this branch (`fteproxy/relay.py`,
`fteproxy/record_layer.py`, `fteproxy/handshake.py`, `fteproxy/__init__.py`,
`fteproxy/stream.py`, `fteproxy/socks.py`, `fteproxy/cli.py`,
`fteproxy/defs/__init__.py`, `fteproxy/defs/parts/dns.json`,
`fteproxy/tests/realism/dns.py`). Every measurement quoted below was taken on
this branch with libfte 0.4 on the author's machine; no source file was changed.

`docs/plan-1.0.md` lists UDP as an explicit non-goal for 1.0.0, and
`docs/plan-formats.md` defers it with one line ("UDP protocols (SNMP, native DNS,
NTP) cannot be mimicked over a TCP tunnel at all; a UDP datagram mode is under
separate feasibility study"). This is that study.

Short version: the cryptography, the key schedule, the allow rules and the SOCKS5
address encoding all carry over unchanged. The record layer needs a real but
bounded change. The relay is a rewrite. The formats are *less* new work than it
first appears — the DNS format and its independent realism parser already ship —
but the capacity floor in `fteproxy/defs/__init__.py` rules out every other UDP
candidate, and the one that survives is capped at about 141 bytes of payload per
datagram. The security story changes in two ways that are not details: over TCP
the three-way handshake proved the client's source address for free and over UDP
nothing does, and the failed-handshake behaviour SECURITY.md documents depends on
holding a connection open, which a datagram transport cannot do.

Recommendation: **not 1.0; the next milestone**, with the U0 spike run first as a
real go/no-go, because the numbers above are close enough to "not worth it" to
deserve a decision rather than an assumption.

---

## 1. The goal, and what it unlocks

### 1.1 Why the transport is the tell

fteproxy shapes *bytes*. It does not shape the transport underneath them. A
covertext that parses perfectly as an SNMP GetRequest, delivered over a TCP
connection to port 161, is SNMP-over-TCP — a thing that has an RFC (RFC 3430,
withdrawn) and essentially no deployment. A classifier does not need to look at a
single byte of the payload to flag it; the 5-tuple is enough. The same holds for
NTP and for native DNS. So for the whole family of UDP-native cover protocols,
the current design cannot get to the starting line, no matter how good the regex is.

This is the entire case for a datagram mode. It is not about performance and not
about carrying UDP application traffic (though it would do that too); it is about
unlocking a set of cover protocols that are unreachable today.

### 1.2 The first filter: a covertext cannot be small

Before any deployment argument, there is a hard floor in the code, and it
eliminates most of the interesting UDP protocols outright.

`fteproxy/defs/__init__.py` sets `MIN_CAPACITY = 128` and `check_capacities`
refuses to load a release containing any format below it; `fteproxy/defs/validate.py`
re-checks the same floor. The reason is the handshake: the client hello is always
sealed as **one format-mode covertext**, regardless of the session's record-layer
mode (`_client_handshake` does `_seal(request_cipher, driver.hello_bytes, 0)`, and
`_accept_hello` replies the same way). So hybrid mode does not rescue a small
covertext — the first datagram in either direction is format mode no matter what.

Measured on this branch, libfte's AE frame costs a flat **29 bytes**: a
maximum-entropy format (`^[\x00-\xff]+$`, every byte free) has capacity
`length − 29`, and below length 30 it raises
`FormatCapacityError('format is too small to hold even an empty encrypted
message')`. So even in the best possible case:

| goal | minimum covertext length |
|---|---:|
| clear `MIN_CAPACITY` (128) | 157 |
| hold a real client hello (46–54 B + the 12-byte seal) | 87–95 |

A real protocol's fixed literals only push those numbers up. **A cover protocol
whose real datagram is shorter than about 160 bytes cannot be an fteproxy format
at all.** That is a code fact, not a taste judgement, and it decides three of the
five candidates below before their traffic models are even reached.

The escapes exist but are not free, and this study does not otherwise propose
them: a *separate, larger* handshake format used only for the first datagram
(which changes what an observer sees at flow start), or a multi-datagram
handshake (which changes the handshake state machine and the reject path). If a
sub-160-byte cover protocol is ever wanted, one of those has to be designed and
budgeted first.

### 1.3 The candidates, honestly assessed

**DNS on 53/udp — the prize, and it is already half-built.**

Value: the highest of any cover protocol. UDP/53 egress is permitted almost
universally, including from captive portals, hotel networks, and restrictive
enterprise egress filters, and it is permitted *before* authentication in many of
them. Nothing else on this list is close.

Expressibility: not a question — it is **shipping**. `fteproxy/defs/parts/dns.json`
holds `dns-request` and `dns-response` as byte regexes at `length` 272,
`mode_hint: format`, `port: [53]`, and they are assembled into the
`fteproxy/defs/20260903.json` release. An independent DNS parser already exists at
`fteproxy/tests/realism/dns.py`: it walks the 2-byte length prefix, the header
counts, the labels, the `0xc00c` pointer and `RDLENGTH`, and it never imports the
regex. So the "write a DNS format and a realism harness" work the earlier draft of
this study budgeted for is already done, for DNS-over-TCP. What remains for UDP is
narrow: drop the 2-byte length prefix, re-pick a length, and re-run
`fteproxy/defs/validate.py` and the realism harness.

The caveat is capacity, and it is much tighter than a length choice. All of a DNS
query's capacity lives in the QNAME, and RFC 1035 §2.3.4 caps the whole encoded
name at 255 octets — which `fteproxy/tests/realism/dns.py` enforces at
`_MAX_NAME_OCTETS`. **The shipped format is already at that ceiling.** Measured
through the shipped parser at `length` 272:

| format | covertext length | capacity | payload (−13 B seal+type) | encoded QNAME |
|---|---:|---:|---:|---:|
| `dns-request` | 272 | 154 | 141 | 254 of 255 octets |
| `dns-response` | 272 | 148 | 135 | 238 octets |

There is one octet of headroom. Running the shipped `dns-request` and
`dns-response` at 280, 300 and 512 all fail the realism parser (immediately, on
the length prefix, which the regex pins as the literal `\x01\x0e` = 270 — but even
after re-picking that literal there is nowhere to put the extra bytes, because the
name is full).

So the DNS inner MTU is about **141 bytes**, and it is a ceiling, not a starting
point. That is small enough to be the study's most consequential number: a
DNS-shaped fteproxy tunnel **cannot carry a real 512-byte DNS query inside
itself**. It is a channel for short messages — control traffic, chat, a shell —
not for arbitrary UDP application datagrams.

So the honest position on DNS is a three-way verdict:

- Against a **signature/DPI classifier** that asks "does this parse as DNS":
  strong. Every datagram parses; that is exactly what FTE is for.
- Against a **stateless request/response consistency check**: it fails today, and
  the check is cheaper than parsing. Nothing in the record layer can make a
  response depend on its request — every covertext is an independent unranking of
  an independently randomised sealed ciphertext (`record_layer._seal` plus
  `fte.FTE.encrypt`, which re-draws per call). In the shipped `dns-response`
  regex the 16-bit ID is a free `[\x00-\xff][\x00-\xff]` and the QNAME is
  generated independently of the query's, so **every response carries an ID and a
  question section that do not match the query it answers**. Resolvers, conntrack
  DNS helpers and DNS-aware middleboxes already do that two-field table lookup.
  `fteproxy/tests/realism/dns.py` grades one message in isolation (its `0xc00c`
  check is intra-message), so the existing harness cannot catch it. This is
  largely moot over TCP; over UDP/53 to a host that is not a resolver it is the
  first thing a DNS-aware box flags. Fixing it means the response covertext has to
  be a function of the request — which the record layer has no mechanism for
  today, and which is not a small change.
- Against a **DNS-tunnel detector**: weak, and the weakness is not in the bytes.
  Long QNAMEs, high per-label entropy, no cache-hit pattern, a constant packet
  size, a unique name per query, a sustained high query rate, and a flow directed
  at a host that is not a resolver are each a well-known and deployed signal.
  Making each datagram parse does not make the *flow* look like DNS.

All three should be stated in SECURITY.md if this is ever built, rather than left
for a user to discover.

**NTP on 123/udp — blocked in code. Do not build for it.**

An NTP packet is 48 fixed bytes, and §1.2 already disposes of it: 48 is far below
the ~160-byte floor. Measured, an NTP-shaped 48-byte regex (four fixed header
bytes, the rest free) holds **15 bytes** — 19 even if every one of the 48 bytes
were free — against a `MIN_CAPACITY` of 128. `check_capacities` refuses to load
the release at all, with `DefinitionsError('these formats cannot carry a handshake
(need 128 bytes of capacity): ... at length 48 holds 15')`. NTP is not "a very
low-rate signalling channel"; **it cannot complete a handshake**, so it is refused
before any traffic-model argument is reached.

For completeness, the realism argument would have killed it anyway. Everything in
an NTP packet that could carry payload is a timestamp, and a plausible timestamp
is a near-real-time NTP-era value with a monotone relationship to the other
three — a constraint a regular language cannot express. And real NTP is one
exchange every 64 to 1024 seconds per peer; a sustained bidirectional NTP flow is
anomalous on its face.

**SNMP on 161/udp — expressible, strategically weak.**

The task framing is right, and worth being precise about why. SNMP is ASN.1/BER:
a nest of type-length-value triples where each length byte must equal the actual
length of what follows it. A regular language cannot enforce agreement between a
length field and the extent of a later field — that is a context-sensitive
constraint. The escape hatch is that a *constant* is expressible: if every message
has the same shape and every field the same width, all the lengths are literals in
the regex, and the payload sits in one OCTET STRING of a fixed size. Such a message
BER-parses correctly. So "regex-FTE cannot do SNMP" is too strong; what is true is
that regex-FTE can only produce **one shape** of SNMP message, forever, with every
field the same width.

That is survivable for a signature classifier. What is not survivable is the
deployment reality: SNMP is a management protocol for internal networks, is very
rarely permitted outbound across an organizational border, and any monitoring
system that does see it knows its own community strings and its own agents. A
sustained SNMP conversation with an external host is a red flag by itself. Low
priority.

**QUIC-shaped on 443/udp — not buildable as a short header, and the wrong tool anyway.**

QUIC is now the highest-volume UDP protocol on the internet, so the flow shape
(sustained, bidirectional, MTU-sized, to port 443) is unremarkable — the opposite
of every other candidate here. And the packet shape is friendly: a long header
begins with fixed bits, a 32-bit version, and length-prefixed connection IDs, and
*everything after the header is AEAD ciphertext by design*. In principle the
correct framing for a QUIC cover is `hybrid` mode: a short formatted header shaped
like a QUIC header, then raw authenticated ciphertext, where hybrid's high-entropy
tail is not a leak but the accurate imitation.

In practice that is not implementable as described, and §1.2 says why: the
handshake is *always* one format-mode covertext, so the formatted header alone has
to clear `MIN_CAPACITY`. A ~30-byte QUIC long header does not come close — even a
30-byte all-free format holds 1 byte. Hybrid mode does not rescue it. A QUIC cover
would need one of the §1.2 escapes (a separate larger handshake format, or a
multi-datagram handshake), neither of which is proposed or budgeted here.

The deeper problem is that it fails the project's own stated test. `docs/plan-formats.md`
argues, correctly, that when the target protocol is itself encrypted the honest
move is to run the real protocol and tunnel inside it, because a hand-rolled
look-alike is weaker than the genuine article. QUIC is that case, and worse: the
Initial packet's header protection and payload use keys derived from the
Destination Connection ID by a *public* algorithm (RFC 9001 §5.2), so any detector
that cares can attempt to decrypt a QUIC Initial and see that it is not one. A
signature classifier is fooled; a QUIC-aware one is not, at negligible cost to it.
If the goal is a QUIC-shaped tunnel, MASQUE or an HTTP/3 tunnel over a real QUIC
stack is the stronger answer.

**STUN on 3478/udp (and on ephemeral ports inside WebRTC) — the best traffic
model on the list, and the one the capacity floor blocks outright.**

A STUN message is a 20-byte header — a 2-byte type with two fixed high bits, a
2-byte length, the fixed magic cookie `0x2112A442`, and a **96-bit transaction ID
that is required to be random** — followed by TLV attributes. The magic cookie is
a literal and the transaction ID is 12 bytes of natively-high-entropy capacity,
which is why an earlier draft of this study ranked STUN second.

That does not survive contact with the code. Measured, a 20-byte STUN header
regex raises `fte.FormatCapacityError('format is too small to hold even an empty
encrypted message')` — 20 bytes cannot even hold the 29-byte AE frame, let alone
the 128-byte floor or a client hello. Twelve free bytes is not "capacity"; it is
less than half a nonce. And hybrid framing does not help, because the handshake is
format mode regardless (§1.2). A STUN cover is only reachable by first designing
one of the §1.2 escapes, and *then* the attributes still have to pad the message
past ~160 bytes, which starts to strain the imitation.

The traffic model remains the genuinely attractive part and is worth keeping on
file: STUN binding exchanges legitimately go to arbitrary hosts, they are
bidirectional, and in real WebRTC they are immediately followed on the same
5-tuple by a high-volume, high-entropy DTLS/SRTP media flow. "A short formatted
STUN exchange, then sustained pseudo-media" is the most plausible *high-volume*
shape available. It is just not buildable on today's floor.

**Summary**

| Protocol | Fits the ~160 B floor | Regex-expressible | Flow plausible | Verdict |
|---|---|---|---|---|
| DNS 53/udp | yes, at 272 B — but capped there | yes; already shipping in `20260903` | passes DPI, fails ID/question echo and a tunnel detector | build first; it is the only reason to do this. ~141 B inner MTU |
| SNMP 161/udp | plausibly, at a padded fixed shape | only as one fixed message shape | poor; rarely crosses a border | skip |
| STUN 3478/udp | **no** — 20 B header raises `FormatCapacityError` | header yes, if it could be built | best on the list | blocked by the capacity floor; revisit only if an escape is designed |
| QUIC 443/udp | **no** — ~30 B long header holds 1 B | header yes, body is entropy by design | excellent | blocked by the floor, and run real QUIC anyway |
| NTP 123/udp | **no** — 48 B holds 15 | timestamps cannot be faked by a regex | very poor; ~1 packet/minute | refused by `check_capacities`; skip |

---

## 2. What the current design assumes, and where a datagram breaks it

Each item names the file and the mechanism.

### 2.1 The record layer frames a byte *stream*, by construction

`fteproxy/record_layer.py` exists because "libfte 0.4 encrypts one message into
exactly one fixed-length covertext and has no stream framing of its own", so this
module supplies the framing. Concretely:

- `Encoder.push` appends to `self._buffer`; `Encoder.pop` slices the whole buffer
  into `self._capacity` chunks and emits one record each. A single `send()` of
  256 KiB becomes many records with no message boundary preserved.
- `Decoder.push` appends to `self._buffer`, and `pop_records` loops
  `while len(buffer) - offset >= self._frame_size`, deliberately leaving a
  trailing partial record buffered for the next read. In hybrid mode
  `_pending_body_len` carries a verified header across several `push` calls while
  its body arrives in pieces.

Every one of those is a stream idea. A datagram is atomic: it arrives whole or not
at all, and bytes never continue into the next one. A datagram record layer wants
the inverse contract — *one datagram in, one record out, or drop* — with no
buffer, no partial-record state, and no `_pending_body_len`. The `Encoder`'s
push/pop path is simply not used; the `_emit` path (which is already one complete
record per call) is. So this is not "adapt the Decoder", it is "a sibling class
that reuses `_seal`/`_unseal` and the cipher objects".

### 2.2 Sequence numbers are a strict equality test, and the decoder is fail-closed

This is the sharpest break, and also the one with the best news hiding in it.

`_seal(cipher, message, seq)` packs `len(4) || seq(8) || message || random pad`
and encrypts. `_unseal(plaintext, seq)` returns `None` unless the embedded
sequence number equals the `seq` the *caller* expected. In `Decoder.pop_records`
that caller passes `self._seq`, a counter that only advances on success:

```python
head = _unseal(head, self._seq)
if head is None:
    ...
    self._failed = True
    break
```

and in hybrid mode the same number is bound into the body tag
(`_AEADBody._tag(seq, nonce, ciphertext)` in `fteproxy/__init__.py`), so a body
verified at the wrong position raises `InvalidTag` and again sets `_failed`.

`_failed` is terminal by design. `Decoder.push` then raises `StreamFailedError`,
and `_FTESocketWrapper._decode` turns either outcome into `self._broken = True`
and logs "closing connection: a record failed authentication". SECURITY.md states
the property positively: "a record that is reordered, replayed, or dropped within
a connection fails authentication and the stream stops."

Over TCP that is exactly right — TCP already guarantees order and delivery, so a
gap *is* an attack or corruption. Over UDP, reorder and loss are the normal case,
and this behaviour would mean **the first lost datagram permanently kills the
session**, and any off-path attacker who can spoof one datagram to a known 5-tuple
gets a remote kill switch. A datagram mode must invert both halves: check the
sequence number against a **sliding replay window** rather than an equality test,
and **silently drop** a datagram that fails rather than failing the session closed.
That inversion is security-relevant and needs saying out loud in SECURITY.md,
because it removes a property the TCP transport currently has. It is also
*asserted* today: `fteproxy/tests/test_record_layer.py` contains
`test_reordered_record_is_rejected` and
`test_reordered_or_replayed_record_is_rejected`, which check that the stream is
marked failed, the buffer dropped, and further pushes refused. So drop-not-fail
cannot be a flag on the existing `Decoder` without breaking a tested, documented
guarantee — it has to be a sibling class, which is the same conclusion §2.1
reaches from the framing side.

The good news: the sequence number is already **on the wire, inside the
authenticated ciphertext**, in both modes. In format mode `_unseal` reads it out
of the sealed plaintext. In hybrid mode the header's sealed plaintext carries the
same `seq` alongside the body length, and the header decrypts under the header key
alone — so a receiver can decrypt the header, *read* the sequence number, check it
against a window, and only then verify the body at that number. No wire-format
change is required to support out-of-order delivery. The change is confined to the
decoder's control flow: replace `_unseal(head, self._seq)` with "unseal at whatever
`seq` the record claims, then run the window check". That materially lowers the
cost of this component, and it is the single most useful finding in this study.

### 2.3 The handshake assumes reliable, ordered, exactly-once delivery

`_client_handshake` (`fteproxy/__init__.py`) does:

```python
self._socket.sendall(sealed)
frame = self._read_exactly(response_cipher.output_format.max_length, timeout)
```

One send, then a blocking read for *exactly* one response covertext, bounded by
`runtime.fteproxy.handshake.timeout` (5 s in `fteproxy/conf.py`). There is no
retransmission anywhere. The server side, `_await_client_hello`, loops on `recv`
accumulating into `_pre_handshake_incoming` until `_server_handshake` finds a
decodable covertext at the front — accumulation across reads being, again, a
stream idea; over UDP the hello either arrived in one datagram or it did not.

Over a lossy connectionless transport, a dropped hello or a dropped server hello
means the handshake simply fails after 5 seconds with no retry. A datagram
handshake needs the standard DTLS/QUIC machinery: retransmit the hello on a timer
with exponential backoff and a bounded attempt count, and treat the arrival of the
peer's reply as the implicit ack.

**And that collides head-on with the replay filter.** `ReplayFilter.observe`
refuses a `c_pub` it has already seen inside the epoch window, and
`accept_client_hello` raises `ReplayedHello` when it does. A client whose *server
hello* was lost retransmits its hello with the **same** `c_pub` — and the server
classifies its own client's retransmit as a replay and answers with silence,
permanently. The client then retries forever and never connects. This is not a
subtle interaction; it would be the first bug anyone hit.

There are two fixes, and the study should price both rather than assume the first.

**Option A — a reply cache.** The one DTLS and QUIC use: cache the computed server
hello per accepted `c_pub` for the epoch window and **re-send the cached reply**
on a duplicate rather than rejecting it, keyed on `(c_pub, source address)` so a
duplicate from the *same* source is a retransmit and a duplicate from a
*different* source stays a replay and gets silence. Re-sending costs no asymmetric
crypto, which matters for §4.1.

**Option B — a fresh ephemeral per attempt.** `ClientHandshake.__init__` draws a
new X25519 ephemeral on every instance, and `transcript_hash` binds the *exact*
hello bytes, which `finish()` then verifies the server MAC against. So a client
can simply retransmit with a **new** `c_pub` and match whichever reply arrives
against the attempt that produced it. `ReplayFilter` never sees a duplicate,
because there isn't one. The cost is one server X25519 keygen plus two DH per
retransmitted attempt (`accept_client_hello`), and the client has to keep one
`ClientHandshake` object per outstanding attempt and try `finish()` against each.
The benefit is that the entire `(c_pub, source)` cache — a new, security-sensitive,
attacker-reachable data structure — never has to exist.

Option B is probably the right default for a first implementation: it moves the
new state to the client, where it is per-session and bounded by the retransmit
count, instead of to the server, where it is per-source and unbounded. Option A is
the optimisation to reach for if handshake CPU turns out to be the constraint. The
choice should be made deliberately, because it is not the free win the DTLS
precedent makes it look like — see §4.1 for why the cache does *not* bound
reflection.

**Duplicate *server* hellos at the client also need a rule.** Retransmission is
symmetric: if the client's first hello arrived and the reply was lost, the client
retransmits and may then receive *two* server hellos, the second after the
handshake has already completed. That second datagram is sealed under `K_cover` at
seq 0, so it will not unseal as a session record — and under today's control flow
(`record_layer.Decoder.pop_records` sets `_failed`, then `_FTESocketWrapper._decode`
sets `_broken`) it kills the session outright. A datagram client needs an explicit
"discard a duplicate server hello" rule alongside the replay window, or the
success case of a retransmit is worse than the failure case.

### 2.4 Session identity *is* the TCP connection today

`listener.run` obtains identity from the kernel: `conn, addr = self._sock.accept()`,
one socket per client, handed to one setup thread, wrapped in one
`_FTESocketWrapper` that privately owns the encoder, decoder, sequence counters
and session keys. Nothing in the protocol names the session, because the file
descriptor does.

With one UDP socket serving every peer, that identity has to come from somewhere,
and both available answers have real costs:

- **The address tuple.** Free, invisible on the wire, and spoofable. It also
  breaks on **NAT rebinding**: a NAT's UDP mapping is bound to an idle timer, and
  30 seconds to 2 minutes is typical (carrier-grade NAT is at the aggressive end,
  and UDP mappings are shorter-lived than TCP ones because there is no FIN to
  observe). A client behind CGNAT that goes quiet and comes back arrives from a
  new port; indexing by tuple means the session is silently gone.
- **An explicit session ID in every datagram.** Survives rebinding, but it is
  **plaintext on the wire and constant for the life of the flow** — a per-flow
  correlator handed directly to the observer, which is precisely the thing the
  rest of the design works to avoid. And there is nowhere plausible to put it: a
  DNS query has a 16-bit transaction ID that is *supposed to vary per query*, so a
  constant one is itself a tell, and 16 bits is too small anyway. QUIC is the only
  candidate on the list with a natural home for it (that is what a Connection ID
  is), which is another reason QUIC-shaped is the easy target and DNS is the hard
  one.

The workable design is the layered one: **address tuple as the fast index; a
session ID sealed *inside* the covertext as the rebinding recovery path.** A
datagram from a known tuple is decrypted with that session's keys directly. A
datagram from an unknown tuple first goes through the existing `K_cover` handshake
scan (it is probably a new client); if that fails, it may be a rebound session, and
the server tries it against the header keys of the *K* most recently active
sessions, with K small and the whole path rate-limited — because each attempt is a
DFA unrank. That is essentially QUIC's connection migration with path validation,
and it is the highest-design-risk item in the whole feature.

### 2.5 The relay's threading model assumes a socket pair

`relay.py` is built around pairs of streams:

- `listener.run` starts one setup thread per accepted connection, and
  `Connection.start` starts **two** `worker` threads per connection, one per
  direction.
- `worker.run` calls `fteproxy.network_io.recvall_from_socket(socket1)`, which does
  `select.select([sock], ...)` then `sock.recv(bufsize)` and treats a zero-length
  read as end of stream (`is_alive = False`). A zero-length **UDP datagram is
  legal** and is not EOF, so that contract is not merely unhelpful, it is wrong.
- `half_close`, the `CLOSE` record, `peer_closed` and `pending_eof` implement
  half-close, which has no datagram analogue at all.
- `Connection` closes both sockets only when both directions have ended — a
  lifecycle driven by stream EOF, which UDP does not have. Sessions must instead
  be reaped by an idle timer.
- `worker.run` sleeps `runtime.fteproxy.relay.throttle` (10 ms) whenever a poll
  yields nothing. PERFORMANCE.md explains that this is load-bearing: it is a GIL
  yield that stops a connection's two workers from convoying. In a single-demux-loop
  design that reason evaporates, and a 10 ms sleep would instead be a flat added
  latency on every datagram — bad for DNS, whose whole point is being fast.

Two threads per session also does not scale to the session counts a UDP tunnel
implies. The data path becomes: one demux thread reading the shared socket, a
session table, and one upstream UDP socket per session (or per session-destination
pair). That is a rewrite of `relay.py`'s data path. The scaffolding around it —
`listener.bind` with its dual-stack `::` bind and IPv4 fallback, the `_connections`
set and its lock, `stop()` — is reusable almost as written, with `SOCK_STREAM`
becoming `SOCK_DGRAM` and `listen()`/`accept()` dropped.

### 2.6 OPEN/OPEN_RESULT presume one destination per connection, and TCP

`fteproxy/stream.py` is in good shape for reuse, with two exceptions.

Reusable unchanged: `encode_address`/`read_address` (the SOCKS5 address
encoding), the status codes, and all of `AllowRules` — `check` and `check_resolved`
are protocol-agnostic and already do the loopback/link-local defence and the
resolve-then-recheck dance.

Not reusable: `stream.connect` is hard-wired to TCP —
`socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)`, then `sock.connect`,
then `setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)`. A UDP dialer is a near-copy with
`IPPROTO_UDP` and no `TCP_NODELAY`, but the *semantics* thin out: there is no
handshake, so most of the SOCKS5 reply codes have nothing to report.
`CONNECTION_REFUSED` in particular arrives, if at all, as a later ICMP error on a
connected UDP socket, long after the OPEN_RESULT was due.

Name resolution is the exception, and it keeps more of the status set alive than
it first appears. `stream.connect` resolves *before* it connects, and a
`socket.gaierror` from `getaddrinfo` is turned into a status synchronously
(`status_for_error(e)`), with an empty candidate list becoming `HOST_UNREACHABLE`.
A UDP dialer does the same resolve and can fail the same way, so
`HOST_UNREACHABLE` and `GENERAL_FAILURE` stay meaningful for a destination that
will not resolve. What a UDP OPEN_RESULT actually loses is the codes that only a
completed transport handshake can report: realistically it collapses to
`SUCCEEDED`, `NOT_ALLOWED`, `ADDRESS_TYPE_NOT_SUPPORTED`, `HOST_UNREACHABLE` and
`GENERAL_FAILURE`, out of the nine `fteproxy/stream.py` defines.

The deeper mismatch is the shape. `OPEN` names one destination for the life of the
connection, because a TCP connection has exactly one. A UDP association naturally
talks to *many* destinations — that is precisely what SOCKS5 UDP ASSOCIATE is: the
association is established once, and every datagram then carries its own
destination header. So the right design is an association-establishing record at
session start plus a SOCKS5 address header on every `DATA` datagram (parsed by the
existing `read_address`, which already takes an offset for exactly this kind of
embedded use). Consequences: the allow rules must be evaluated **per datagram**,
not once per session, and a resolved-name cache is needed so a datagram does not
cost a `getaddrinfo`.

### 2.7 SOCKS5 UDP ASSOCIATE is currently, deliberately, refused

`fteproxy/socks.py` defines `CMD_UDP_ASSOCIATE = 0x03` and `read_request` raises
`SocksError(..., COMMAND_NOT_SUPPORTED)` for any command that is not CONNECT — a
proper refusal rather than a hang, as the module docstring says. Implementing it
means:

1. Keep the TCP control connection open; the association lives and dies with it
   (RFC 1928 §7). The current listener has no notion of a control connection that
   outlives its request.
2. Bind a local UDP socket and report **its real address** in the reply. Note that
   `send_reply`'s `bound` parameter defaults to `('0.0.0.0', 0)` and its docstring
   explains that for CONNECT nobody cares. For UDP ASSOCIATE the client sends its
   datagrams to that address, so `0.0.0.0` breaks essentially every client. That
   docstring will need a caveat.
3. Read and honour the ASSOCIATE request's **own** `DST.ADDR`/`DST.PORT`. This is
   not the destination — it is the address the client expects to *send its
   datagrams from*, and the proxy is supposed to accept datagrams only from that
   peer. `read_request` never gets that far today: it raises on
   `command != CMD_CONNECT` before reading the address at all. In practice clients
   very often send `0.0.0.0:0` ("I don't know yet"), so the policy has to be
   "learn the peer from the first datagram, then pin it" — which is a small piece
   of per-association state with a security purpose, not a field to ignore.
4. Parse the SOCKS5 UDP request header on every datagram:
   `RSV(2) || FRAG(1) || ATYP || ADDR || PORT || DATA`. Reject any non-zero `FRAG`,
   as every implementation does.
5. **Re-encapsulate the return path.** A reply from the remote must be wrapped in
   a SOCKS5 UDP header naming *the remote's* address before it goes back to the
   application. That is the item with the largest structural consequence: it means
   the **client-side** listener has to keep its own demux table (association →
   application peer, and remote → association), not just the server end. §2.5's
   "one demux thread and a session table" is therefore needed twice, once at each
   end, with different keys.

None of that is conceptually hard; items 3 and 5 are the ones that were missing
from the effort estimate.

---

## 3. Required changes, component by component

"Extension" means the existing code grows a case. "Rewrite" means a new
implementation alongside the current one.

| Component | Change | Kind |
|---|---|---|
| UDP listener / dialer | `SOCK_DGRAM` listener reusing `listener.bind`'s dual-stack logic; a `stream.connect_udp` sibling with `IPPROTO_UDP` | extension |
| Datagram record layer | `DatagramEncoder`/`DatagramDecoder` reusing `_seal`/`_unseal` and the ciphers; sequence window; drop-not-fail | rewrite (small; shares the primitives) |
| Handshake | retransmit with backoff; either a fresh ephemeral per attempt or a `(c_pub, source)` reply cache; duplicate-server-hello discard | extension |
| Session table | keyed by tuple, with a sealed session ID as the rebinding path; idle reaping; keepalives | new |
| Relay data path | demux loop + session table + per-session upstream sockets, replacing the worker pair | rewrite |
| Client listener | SOCKS5 UDP ASSOCIATE (including the return-path demux table), and a `-U` UDP forward | extension + new |
| Per-format mode policy | server-side refusal of `hybrid` for datagram-parsed formats; a new `InvalidHello` reason | new |
| Formats | a UDP variant of the shipped `dns` pair, plus the length/amplification invariant | extension |
| CLI / config | repeatable `--listen`, transport selection on both ends, `?transport=` on both parse and emit | extension |
| Security hardening | pre-crypto rate limits, amplification invariant in `defs-check`, per-transport SECURITY.md wording | new |

### 3.1 The record layer, in detail

One covertext per datagram, and — for every format-mode target — the datagram is
*exactly* one covertext, so `Decoder._frame_size` becomes a validity check: a
datagram whose length is not `cipher.output_format.max_length` is dropped without
decrypting.

The sequence-number handling becomes a replay window, standard IPsec/DTLS style: a
64-bit high-water mark plus a 64-bit bitmap of recently-seen positions below it.
A record whose sealed `seq` is above the mark advances it; one inside the window
and unseen is accepted and marked; one below the window or already marked is
dropped. Because the sequence number is inside the authenticated ciphertext
(§2.2), an attacker cannot move the window without the keys — the window is
consulted *after* authentication, never before.

Hybrid mode should be **refused** for datagram-parsed formats such as DNS, and it
is worth being explicit both about why and about the fact that nothing in the code
can do it today.

Why: over TCP, hybrid is defensible because a byte stream has no boundaries an
observer can parse, so a formatted header followed by entropy is just "some
bytes". A UDP datagram is a *complete protocol message* and is parsed as one: a
DNS response with high-entropy garbage after the header does not parse, and fails
the very check the format exists to pass. So the DNS path is format-mode only —
which pins its throughput (see §3.2).

Why it is unbudgeted work rather than a config line: the server has **no mode
policy**. `handshake.accept_client_hello` validates the definitions release, the
format name, the epoch and the replay filter, and `ClientHello.decode` validates
the version and the reserved flag bits — mode is not checked anywhere.
`_accept_hello` then builds the channel straight from `hello.mode`. The
`mode_hint` in `fteproxy/defs/__init__.py` is explicitly advisory ("the client's
`--mode` still overrides it"), and `fteproxy/defs/validate.py` deliberately
exercises a `hybrid` format in *both* modes for exactly that reason. Enforcing a
per-format mode restriction means a new server-side policy check and a new
`InvalidHello` reason, answered by the same silence as every other rejection.
Hence its own row in the table above.

### 3.2 MTU, capacity, and the cost of a bigger covertext

The task framing asks for covertexts that fit ~1400 bytes; the real finding is
that today's formats are far *smaller* than that, and that growing them is not
free. Measured on this branch (libfte 0.4, this machine), using the new
`http-request` regex from `fteproxy/defs/parts/http.json`:

| covertext `length` | `max_plaintext_bytes` | format-mode payload (−13 B seal+type) | encrypt | decrypt |
|---:|---:|---:|---:|---:|
| 256 | 106 | 93 | — | — |
| 512 | 303 | 290 | 0.37 ms | 0.30 ms |
| 1232 | 857 | 844 | — | — |
| 1400 | 986 | 973 | 2.39 ms | 2.01 ms |

Two things follow.

**Payload per datagram is small, so the inner MTU must be clamped.** The shipped
`20260110` formats are 224–400 bytes (except `binary` at 1320, whose capacity is
only 136 because a `^[01]+$` language carries ~0.1 bytes per byte), and the
`20260903` parts in `fteproxy/defs/parts/` are 256–512: `http` 512/512,
`sip` 512/512, `smtp` 320/256, `ftp` 256/256, and **`dns` 272/272**. A 512-byte
covertext carries 290 payload bytes; a 1232-byte one carries 844. Since a
full-size inner UDP datagram is ~1400 bytes, **no realistic cover format carries
one inner datagram in one cover datagram**. The choices are to fragment an inner
datagram across cover datagrams — which reintroduces reassembly state and
multiplies the effective loss rate, since losing any fragment loses the whole
inner datagram — or to clamp the tunnel's inner MTU to the format's payload
capacity and let applications deal with it. Most UDP applications do not do
path-MTU discovery, so oversized datagrams simply disappear. This needs to be a
documented, per-format number, not a surprise.

**For DNS specifically, the number is not a choice.** It is tempting to reach for
1232 (the IPv6 minimum-MTU-safe UDP payload and the DNS flag-day-2020 recommended
EDNS buffer size), or for the classic 512-byte limit. Neither is reachable: as
§1.3 measures, the shipped DNS format is already at the RFC 1035 255-octet QNAME
ceiling at `length` 272, and running it at 280, 300 or 512 fails the realism
parser. The DNS inner MTU is **~141 bytes** (capacity 154 at length 272, minus 13
for the seal and type byte), and dropping the 2-byte TCP length prefix for the
native UDP message changes that by two bytes, not by an order of magnitude. Any
plan that reasons from 290 or 844 payload bytes for a DNS-shaped format is
reasoning from a length that format cannot have.

The corresponding measured cost, on this machine: `dns-request` at 272 encrypts in
0.145 ms and decrypts in 0.132 ms, so about **3600 datagrams/s and ~4.1 Mbit/s** of
payload per core one-way. The small covertext is at least fast.

**The DFA cost is superlinear in covertext length.** 0.37 ms to encrypt at 512
bytes, 2.39 ms at 1400 — roughly 6.5× the time for 2.7× the bytes. Over TCP,
hybrid mode amortizes one header over a body of up to 1 MiB, which is why
PERFORMANCE.md reports 650–950 MB/s. A format-mode UDP tunnel gets no
amortization at all: every datagram pays a full rank *and* unrank. At 512 bytes
that is about 1500 datagrams/s and ~3.6 Mbit/s of payload per core one-way; at
1400 bytes about 230 datagrams/s and ~1.8 Mbit/s; at DNS's 272 bytes about 3600
datagrams/s and ~4.1 Mbit/s.

Those are the honest ceilings. The right thing to compare them against in
PERFORMANCE.md is its TL;DR figure of "**4–7 Mbit/s bulk**" for format mode, which
they sit just under — *not* the 0.9–1.9 MB/s in its record-layer table, which is
7–15 Mbit/s and roughly two to four times higher. (The gap is amortisation: the
table measures 4 KiB and 1 MiB messages chunked into many records with one
`push`/`pop` each, while a datagram tunnel pays per-record overhead on every
single datagram. An earlier draft of this study cited the MB/s figure as if it
agreed with a Mbit/s one; it does not.)

Fine for DNS lookups, interactive traffic and messaging; not a video path.
Choosing a larger covertext for capacity actively *costs* throughput, which is a
counterintuitive tradeoff worth writing into the format-authoring guide.

### 3.3 Handshake, session table, keepalives

Handshake: retransmit the client hello on a timer (1 s, doubling, ~4 attempts
inside a 15 s budget); the server hello is the ack. Resolve the retransmit-versus-
replay collision by §2.3's Option B (a fresh ephemeral per attempt, so no
duplicate `c_pub` ever reaches `ReplayFilter`) unless handshake CPU proves to be
the constraint, in which case Option A's `(c_pub, source) -> server_hello_bytes`
cache is the fallback. Note that neither option bounds reflection — §4.1 explains
why the cache in particular does not — so the reflection defences have to be the
response-length invariant and a pre-crypto rate limit regardless of which is
chosen. The client must also discard a duplicate *server* hello rather than
feeding it to the session decoder (§2.3).

Session table: `(source tuple) -> session`, with a sealed session ID for
rebinding recovery, an idle timer (a DNS-shaped session might reasonably idle
30 s; a bulk one much longer), and a hard cap on live sessions.

Keepalives: a NAT mapping dies in 30 s to 2 minutes of silence, so an idle session
must emit something. The `PADDING` record type (`0x03`) already exists and is
already "ignored on receipt; reserved for traffic shaping" — it is exactly the
right carrier, and it needs no protocol change. But the *interval* is a
fingerprint: a datagram every 25 seconds, forever, from a client that is otherwise
idle, is a pattern no real DNS client produces. Jitter it, and accept that a
long-idle tunnel is more detectable than a busy one.

### 3.4 CLI and config surface

Additive rather than a new pair of subcommands, but not quite as small as it looks
— two of the four items pull on existing single-valued assumptions:

- `fteproxy server --listen udp/:5353` (or `--transport udp`), **repeatable**, so
  one process can serve both. That is a real change: `--listen` today is
  `server.add_argument('--listen', ..., default=DEFAULT_LISTEN)` with no
  `action='append'`, and the client path calls
  `run_startup_check(args, listeners[0], uri)` — a single-listener assumption that
  a second transport breaks. The server already writes a connection string; it
  would write one per transport.
- `?transport=udp` on the connection string. The *parse* side is free — unknown
  query keys are ignored by design — but the **emit** side is not:
  `ConnectionString.format()` in `fteproxy/config.py` builds its query from a
  fixed `[('format', …), ('mode', …), ('defs', …)]` list, so a new key has to be
  added there or the URI will not round-trip.
- Client: `-U [BIND:]PORT:HOST:PORT` as the UDP sibling of `-L`, and SOCKS5 UDP
  ASSOCIATE available automatically on the existing `-D` listener.
- The startup check (`run_startup_check`) works as-is over UDP once the handshake
  retransmits, and becomes *more* valuable, because a UDP misconfiguration
  otherwise produces silence.

There is a piece of forward-compatibility hygiene already in place, though it is
narrower than it sounds: `handshake.FLAG_RESERVED_MASK = 0xFE` means a 1.0 server
refuses any hello with a reserved flag bit set, with
`InvalidHello('reserved flag bits set')`, answered by silence. A 1.0 server only
ever binds `SOCK_STREAM` (`listener._bind_socket` in `fteproxy/relay.py`), so it
will never *see* a UDP hello — the reserved-bit refusal only bites when a
UDP-capable client reaches a 1.0 server **over TCP**, which is exactly the
misconfiguration worth handling cleanly. So: correct hygiene, and a reason a UDP
mode should claim flag bit 1 (or bump `PROTOCOL_VERSION`), but not a guarantee
about UDP traffic. Nothing in 1.0 needs to change today to keep that door open.

---

## 4. Security, specific to UDP

### 4.1 Reflection and amplification

**The reject path does not carry over, and SECURITY.md has to say so.** The bullet
as written is: "no reply, read and discard for a random 1 to 5 seconds, then
close, and one line in the DEBUG log". Over UDP only the *first* clause survives.
`_begin_reject`, `_discard_until_deadline` and `reject_and_close` all operate on a
held-open TCP connection, and `handshake.reject_delay()` exists specifically to
make a **connection lifetime** untimeable — obfs4's trick of looking like "a
service with nothing to say". A datagram transport has no connection to hold and
none to close, so there is nothing for the random delay to hide behind and nothing
for a prober to time.

What replaces it is simpler and weaker: a datagram that does not unseal under
`K_cover` gets **nothing**, ever, and the server keeps no per-source state for it
(keeping state would be the amplification vector of the third point below). The
indistinguishability property is preserved — every rejection reason is still
answered identically — but the mechanism that delivers it is different, and the
SECURITY.md bullet must be rewritten **per transport** rather than carried over.
That is a documentation change with a real reader-facing consequence, not a
formality.

Beyond the reject path, UDP adds three things TCP did not have:

**The server must never be an amplifier for the datagrams it *does* answer.** The
only unsolicited reply the server ever sends is the server hello, and it sends it
only to a hello that authenticated under `K_cover`. `K_cover` is derived from the
server's *public* key, so **anyone holding the connection string can make the
server send a covertext to a spoofed source address**. Over TCP this was
impossible — a SYN had to be answered and acknowledged first. The mitigation is an
invariant on the definitions release: **the response covertext length must be less
than or equal to the request covertext length**, so the amplification factor never
exceeds 1. Today's `20260110` pairs are all equal-length except `ftp` (264 request
/ 296 response, 1.12×), and the `20260903` parts already satisfy it (`http` and
`sip` 512/512, `ftp` 256/256, `smtp` 320 request / 256 response, `dns` 272/272).
That invariant is one assertion in `fteproxy/defs/validate.py` and should be added
to `defs-check` if a UDP release ever ships.

Be clear about what factor 1 does and does not buy, though. It caps the *bytes*,
but the server is still a **reflector that launders the attacker's source
address** — a spoofed hello produces a same-size covertext delivered to a victim
who cannot tell where it came from — and it still pays an X25519 keygen plus two
DH plus HKDF per spoofed datagram (`accept_client_hello`). Factor 1 is a
necessary bound, not a solution.

And note what does *not* bound it: a reply cache (§2.3, Option A) is no defence
here. `cover_key()` is derived from the server's **public** key, so an attacker
holding the connection string mints a fresh `c_pub` for every spoofed source,
never hits a cache entry twice, and never trips `ReplayFilter.observe()`. "Bound
the re-sends per cache entry" bounds nothing an attacker cares about. The only
real bounds are the response-length invariant above and a **pre-crypto rate
limit** below.

That invariant collides with realism for DNS specifically, and the collision is
worth naming: a *realistic* DNS exchange is a short query and a long response —
which is exactly why DNS is the internet's favourite amplifier. Equal-length
query and response is a (mild) realism cost. There is a pleasing way out: DNS
Cookies (RFC 7873) exist precisely so a DNS server can demand return-routability
before sending a large answer, so a cookie-style round trip is not only the
standard mitigation, it is *protocol-realistic for this particular cover*.

**Silence must be real silence, including from the kernel.** A UDP port with
nothing bound produces an ICMP port-unreachable, which is an answer to a prober in
the same way a TCP RST is. The listening socket must stay bound for the life of
the process, and the deployment notes should say so.

**Computational amplification, even with no reply.** Over TCP, garbage is bounded
by the accept queue, by `_MAX_PRE_HANDSHAKE_BYTES` (64 KiB) and by the handshake
deadline. Over UDP, every unknown-tuple datagram triggers a first-record scan —
`_request_scan_order` walks every `-request` format in the release (23 of them in
`20260110`), most-recently-matched first, doing a DFA unrank per candidate.
Measured, a 512-byte format decrypt is ~0.30 ms, so the MRU hit alone saturates a
core at roughly 3000 spoofed datagrams/s and a full scan much sooner. Past that,
`accept_client_hello` does an X25519 keygen plus two DH plus HKDF per hello. A
UDP mode therefore needs a cheap pre-crypto filter (a per-source token bucket and
a global handshakes-per-second cap) before it does any ranking or any asymmetric
work.

**Two pieces of module-global handshake state land on that hot path.**
`fteproxy/__init__.py` defines `_last_matched_format` and `_replay_filter` as
process globals. Over TCP each is touched once per accepted connection, from a
per-connection setup thread, which is unremarkable. With one shared UDP socket and
a demux thread they become cross-session shared state on the busiest code path in
the server:

- `_request_scan_order()` orders the first-record scan by `_last_matched_format`,
  most-recently-matched first. Anyone holding the connection string can therefore
  **steer** the MRU entry by sending one valid hello in an unusual format, pushing
  every subsequent unknown-tuple datagram to the back of a 23-candidate scan. It
  is only a performance effect — a wrong guess costs the rest of the scan — but
  over UDP it multiplies the cost of the attack in the paragraph above, and it is
  attacker-controlled.
- `ReplayFilter` takes a lock on **every accepted hello**, so under a handshake
  flood it is a single point of contention for the whole process, not just for one
  connection.

Neither is a correctness bug today. Both should be re-scoped (per-listener rather
than per-process) or explicitly rate-limited before they sit behind a shared
datagram socket.

### 4.2 Source-address spoofing and the replay window

Injection into an established session is not the risk it looks like: every
datagram is AE-authenticated under a per-direction session key, so a spoofed
datagram fails authentication regardless of how good the attacker's guess at the
5-tuple is. The risk is what the *failure* does — and, as §2.2 sets out, today's
answer is to kill the stream. Under UDP that turns any off-path spoofer into a
remote kill switch, so the datagram decoder must drop silently. This is a genuine
loss of a property: over TCP, "a record that fails to authenticate stops the
stream" is a strong, clean statement, and the UDP transport cannot make it. It
should be documented per-transport rather than quietly weakened.

The replay window itself (§3.1) restores most of what strict sequencing gave: a
duplicated or replayed datagram inside the window is dropped, one below it is
dropped, and one above it advances the window — all after authentication, so the
window cannot be dragged forward by an attacker without the keys.

### 4.3 The observability of a UDP handshake, and of the flow

The two handshake records are one request-format covertext and one response-format
covertext, exactly as over TCP — SECURITY.md's "same shape as any other record"
holds. What changes is that over UDP they are the first two *datagrams* of the
flow, and datagram boundaries are visible where TCP segment boundaries mostly are
not. A fixed-size datagram exchanged once at flow start, followed by same-size
datagrams in both directions, is a distinctive opening.

More importantly, and this is the point that should temper enthusiasm for the
whole feature: **FTE shapes datagrams, not flows.** A DNS-shaped tunnel produces
a sustained, symmetric, high-rate flow of maximum-length queries to a single host
that is not a resolver, with a unique high-entropy name per query and no cache
behaviour. Every one of those is a signal, and none of them is affected by how
good the regex is. The feature is worth building because it defeats a large class
of deployed signature classifiers and opens paths that are currently closed; it is
not worth overselling to anyone facing a detector built for DNS tunnels
specifically.

### 4.4 What TCP was giving for free

Worth listing plainly, because each item becomes explicit work:

- **Return routability.** The three-way handshake proved the client's source
  address before the server did anything expensive. Nothing in UDP does. (§4.1)
- **Ordering and retransmission.** The sequence-number equality check and the
  fail-closed decoder are only reasonable because TCP guarantees both. (§2.2)
- **Session identity and teardown.** The file descriptor was the identity; FIN or
  RST was the teardown. Both become protocol state and timers. (§2.4, §3.3)
- **Flow control and backpressure.** `sendall` blocks when the peer is slow, so a
  fast source is throttled end to end. UDP has none: a source faster than the
  tunnel's ~1500 datagrams/s just loses datagrams, invisibly, and the tunnel
  becomes the loss source. The `_AEADBody.max_plaintext_bytes` cap and the
  decoder's `max_record_bytes` bound are stream-shaped answers to a problem that
  reappears in a different form.
- **Path MTU.** TCP segments to the path MTU. UDP fragments or drops, and the
  tunnel has to clamp the inner MTU itself. (§3.2)
- **Liveness.** A dead TCP connection reports an error. A dead UDP session is
  indistinguishable from an idle one until a timer says otherwise.

---

## 5. Effort, phasing, and recommendation

### 5.1 By component

- **UDP listener and dialer — small.** `listener.bind`'s dual-stack `::` bind with
  IPv4 fallback is reusable as written with `SOCK_DGRAM`; `stream.connect_udp` is a
  near-copy of `stream.connect` with `IPPROTO_UDP`.
- **Datagram record layer — medium.** Smaller than it first appears, because the
  sequence number is already inside the authenticated ciphertext and can simply be
  read out (§2.2), so `_seal`/`_unseal` and the ciphers are reused unchanged. The
  work is a sibling encoder/decoder pair, a replay window, and inverting
  fail-closed to drop-silently — plus the tests for loss, reorder and duplication,
  which are most of the effort.
- **Handshake retransmit and the retransmit-vs-replay split — small to medium.**
  The crypto and the record encodings do not change at all. §2.3's Option B (a
  fresh ephemeral per attempt) makes this materially cheaper than the earlier
  draft assumed, because it needs no server-side reply cache — the new state is a
  short list of outstanding `ClientHandshake` objects on the client. Option A's
  `(c_pub, source)` cache, if it is ever needed, is the medium case: a new,
  security-sensitive, attacker-reachable structure that has to be bounded as
  carefully as `ReplayFilter` already is. Either way, add the duplicate-server-hello
  discard rule (§2.3).
- **Session table and NAT handling — medium to large, and the highest design
  risk.** Tuple indexing is easy; rebinding recovery is a genuine
  covert-channel-versus-usability tradeoff (§2.4) with no free answer, and it is
  the item most likely to need a second attempt after real-world testing behind
  carrier NAT.
- **Relay data path — large.** `Connection`, `worker`, and
  `network_io.recvall_from_socket`'s stream contract are all replaced by a demux
  loop plus per-session upstream sockets. The listener scaffolding survives; the
  data path does not. This is the single biggest chunk.
- **SOCKS5 UDP ASSOCIATE and a `-U` forward — medium to large.** Larger than the
  earlier draft allowed. The three-item version of §2.7 was incomplete: the
  ASSOCIATE request's own `DST.ADDR`/`DST.PORT` and the associated-peer policy are
  extra state, and the **return path** forces a demux table on the *client* side
  too, not just the server's. The control-connection lifetime and reporting a
  genuinely reachable bound address remain the fiddly parts.
- **Per-format mode policy — small, but genuinely new.** §3.1: `accept_client_hello`
  has no mode check and `mode_hint` is advisory, so refusing `hybrid` for a
  datagram-parsed format needs a server-side policy and a new `InvalidHello`
  reason. Small, and previously unbudgeted entirely.
- **UDP format family — small to medium, and much smaller than the earlier draft
  assumed.** DNS is the only viable candidate (§1.2 rules out STUN, QUIC-shaped
  and NTP on the capacity floor), and DNS is largely **already built**: the regex
  pair ships in `fteproxy/defs/parts/dns.json` and `20260903`, and the independent
  parser ships at `fteproxy/tests/realism/dns.py`. The remaining work is dropping
  the 2-byte TCP length prefix, re-picking a length under the 255-octet QNAME
  ceiling, re-running `fteproxy/defs/validate.py` and the realism harness, and
  adding the length/amplification invariant. Documenting the ~141-byte inner MTU
  and the ID/question-echo gap honestly is part of the deliverable.
  - The one *large* thing hiding in here is optional and should be scoped
    separately: making the response covertext echo the request's ID and question
    (§1.3) has no mechanism in the record layer today, and would be a protocol
    change, not a format change. Without it the format fails a stateless
    consistency check that DNS-aware middleboxes already perform.
- **CLI and config — small.** A transport flag, a `?transport=` hint, `-U` — plus
  making `--listen` repeatable, unwinding `listeners[0]` in `run_startup_check`,
  and adding the new key to `ConnectionString.format()`'s emit side (§3.4). Still
  small, just not zero.
- **Security hardening — medium.** Rate limits before any ranking, the
  response-length invariant in `defs-check`, re-scoping the module-global
  handshake state (§4.1), the per-transport rewrite of SECURITY.md's failed-
  handshake bullet, and possibly a cookie exchange.
- **Test infrastructure — medium to large.** There is nothing today that
  simulates loss, reorder, duplication or NAT rebinding, and without it none of
  the above can be trusted. Build it in the first phase, not the last. Note that
  `fteproxy/tests/test_record_layer.py` already has
  `test_reordered_record_is_rejected` and
  `test_reordered_or_replayed_record_is_rejected`, which assert the **opposite**
  invariant — stream marked failed, buffer dropped, further pushes refused. That
  is not an obstacle; it is the argument for §2.1's conclusion, since flipping
  drop-not-fail inside the existing `Decoder` would break a tested, documented
  guarantee. The datagram decoder has to be a sibling class, and it needs its own
  test file asserting the inverse.

### 5.2 Suggested phasing

- **U0 — spike, capacity and realism first.** Before any transport work. Not "at
  512 and 1232 bytes" — those lengths are unreachable for a DNS-shaped format
  (§1.3), and asking for them is how the earlier draft of this study talked itself
  into a payload figure six times too large. The right question is: **derive the
  maximum covertext length a DNS query can have under the RFC 1035 255-octet
  QNAME ceiling, and measure the capacity and per-datagram cost there.** Start
  from the shipped `fteproxy/defs/parts/dns.json` pair, drop the 2-byte TCP length
  prefix, and grade the result with the shipped
  `fteproxy/tests/realism/dns.py` — both already exist, so this is a day, not a
  phase. Then decide whether ~140 bytes of payload per datagram at ~3600
  datagrams/s is a transport worth building a second relay for. If it is not, stop
  here; that is the cheapest possible way to learn it. Bring the ID/question-echo
  gap (§1.3) into the same decision, since it may turn out to be the real blocker.
- **U1 — datagram record layer, in isolation.** The encoder/decoder pair, the
  replay window, drop-not-fail, and a loss/reorder/duplication test harness. No
  sockets. Fully unit-testable.
- **U2 — a minimal UDP transport.** Handshake with retransmit (fresh ephemeral
  per attempt), the duplicate-server-hello discard, a tuple-keyed session table
  with idle reaping, the demux relay, and a fixed destination (`-U`). Deliberately
  no NAT rebinding recovery yet.
- **U3 — hardening and NAT.** Pre-crypto rate limits, the amplification invariant
  in `defs-check`, re-scoping `_last_matched_format` and `_replay_filter` off the
  process globals, keepalives via `PADDING`, and the rebinding path.
- **U4 — the format.** DNS only — STUN, QUIC-shaped and NTP are blocked by the
  capacity floor (§1.2) and there is no second candidate to sequence after it.
  Mostly a re-length and re-validation of the shipped `dns` pair, plus the
  per-format mode policy, plus the format-authoring notes on the QNAME ceiling,
  the inner MTU and the superlinear DFA cost. Decide separately whether to take on
  request/response echo.
- **U5 — SOCKS5 UDP ASSOCIATE, docs, SECURITY.md.** Including the return-path
  demux table, the per-transport qualifier on the authentication-and-ordering
  guarantee, the rewritten failed-handshake bullet (§4.1), and the honest
  paragraph about flow-level detectability.

### 5.3 Recommendation: the next milestone, not the 1.0 line

Three reasons, in order of weight.

**It is a second transport, not an option on the existing one.** The record
layer, the relay data path, the session model, the handshake state machine and the
listener all change, and the client's SOCKS5 listener grows a demux table of its
own (§2.7). `docs/plan-1.0.md` was right to list UDP as a
non-goal, and nothing found here argues otherwise — if anything the relay rewrite
(§2.5) and the session-identity tradeoff (§2.4) are larger than that plan
anticipated.

**Shipping 1.0 first costs the UDP work nothing.** The handshake, the key
schedule, `_seal`/`_unseal`, the record types (including `PADDING`, which is the
keepalive carrier), the SOCKS5 address encoding, `AllowRules`, the state directory,
the connection string, and the whole `dns` format and its realism parser are all
reused unchanged or nearly so. `FLAG_RESERVED_MASK` means a UDP-capable client
that reaches a 1.0 server over TCP is refused safely and silently (§3.4), and the
connection string parser already ignores unknown query parameters. There is no
compatibility debt to pay by waiting, and no 1.0 change needed today to keep the
door open.

**The value is real but much narrower than it looks, and knowing that should come
first.** Native DNS genuinely is the highest-value channel and genuinely is
unreachable today — that part of the motivation holds up completely, and it is now
the *only* part that does. Three findings narrowed it during this review:

- `MIN_CAPACITY = 128`, plus a handshake that is always one format-mode covertext,
  eliminates **three of the five candidates in code** — NTP, a bare STUN header
  and a bare QUIC long header cannot be fteproxy formats at any length they
  plausibly have (§1.2).
- The one surviving candidate is capped at about **141 bytes of payload per
  datagram** by the RFC 1035 QNAME ceiling (§1.3), which is small enough that the
  tunnel could not carry a real DNS query inside itself.
- And that candidate's responses do not echo their queries' ID or question
  section, which is a cheaper check than parsing and one that DNS-aware
  middleboxes already run (§1.3).

None of that changes the *shape* of the estimate — this is still a second
transport, still large, still not 1.0 — but it does move weight around inside it:
the format work is much smaller than the earlier draft assumed (DNS is mostly
built; there is no second format to build), while the SOCKS5 return path, the
per-format mode policy and the security wording are larger or were missing
entirely. Net: unchanged in magnitude, and rather more concentrated in the relay
and the session model.

It also raises the value of U0 sharply. The spike is now the cheap way to find out
whether a ~141-byte inner MTU with unmatched query IDs is a transport anyone wants,
*before* committing to a relay rewrite — and it is a day's work, not a phase,
because the regex and the parser both already exist.

Suggested framing: **the next milestone after 1.0**, with U0 runnable now as a
standalone experiment and treated as a genuine go/no-go rather than a formality.
