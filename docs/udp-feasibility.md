# UDP feasibility study

Originally written on 2026-09-03; updated to distinguish current TCP behavior
from proposed UDP work. **UDP is not implemented.** This is a design study,
not an implementation plan approved for a release.

The useful finding is that record cryptography could be reused, but UDP needs
a different framing, replay, session, and relay model. A DNS-shaped experiment
should establish usable payload capacity and request/response consistency
before committing to that work.

## What exists today

fteproxy opens TCP sockets, carries byte streams, and supports SOCKS5 CONNECT
and fixed TCP forwards. BIND and UDP ASSOCIATE are refused.
The `dns` format is **DNS over TCP**, not a UDP transport.

The current DNS pair uses `framing: length-prefix` and eight wire lengths
from 90 to 272 bytes. Its regex describes the message behind the two-byte
prefix. Handshakes use the maximum length; format-mode data varies per record.

At the maximum shipped length:

| Direction | TCP wire bytes | Message bytes | Cipher plaintext capacity | Format payload after seal/type |
|---|---:|---:|---:|---:|
| Request | 272 | 270 | 154 | 141 |
| Response | 272 | 270 | 148 | 135 |

These are capacities of the current grammar, not a universal DNS payload limit.
At this length the encoded query name is 254 octets in requests and 238 in
responses. DNS limits a name to 255 octets, so merely lengthening the request
regex soon produces invalid names.
[DNS limits and TCP framing are specified in RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4).

Removing the TCP prefix while keeping the same 270-byte message changes the
wire size, not the cipher's plaintext capacity. New UDP session identifiers,
addresses, or fragmentation headers would reduce the application budget.
Additional DNS records or a different grammar could change the capacity;
that would need a new format and validation.

The loader requires 128 plaintext bytes at the handshake length. This blocks
small message grammars under the current single-covertext handshake design.
A 20-byte STUN header or a basic 48-byte NTP packet cannot carry that much
plaintext. It does not prove that larger messages, extensions, or a redesigned
handshake are impossible.

## Candidate assessment

These are design judgments, not claims that a particular network permits a
protocol or that a format evades deployed classifiers.

| Candidate | Main issue |
|---|---|
| DNS | Existing binary grammar is a starting point, but capacity is small and responses are independent of requests |
| NTP | Basic packet size is below the current handshake floor; timestamp relationships require protocol logic |
| STUN | A header-only cover is too small; attributes, transactions, and flow behavior need a complete design |
| SNMP | Bounded message shapes can be described, but BER lengths and correlated request/reply fields need care |
| QUIC | A header-shaped regex does not implement QUIC; a real QUIC transport would be a separate approach |

A bounded protocol can be represented by a finite language in principle.
The practical obstacle is an efficient grammar that expresses useful lengths,
field relationships, and capacity. The earlier study's claim that regexes
cannot express any length relationships was too broad.

DNS request/reply consistency is a key blocker. The current response ID and
question are generated independently of the request. They are not constructed
to match it, even though each message passes the standalone parser.
This matters over TCP as well as UDP. A UDP carrier would also have to address
high-entropy names, message rates, timing, and destination selection; correct
message syntax alone does not establish a convincing flow.

## Required transport changes

### Atomic records and replay

The current encoder chunks a byte stream; the decoder retains partial records
between reads. A datagram decoder instead needs one datagram to yield one
complete record or be dropped. Datagram boundaries must never be reconstructed
by concatenating separate receives.

TCP decoding expects the next exact sequence number and treats invalid records
as terminal. UDP naturally loses, reorders, and duplicates datagrams.
It needs a separate decoder with an authenticated sliding replay window:
verify the record, read its sealed sequence number, then update the window.
An invalid datagram must not terminate an otherwise valid session.

The sequence number is already inside the authenticated seal. Hybrid body tags
also bind it. Those primitives may be reusable, but `_unseal` currently
requires an expected sequence value, so a datagram API must expose the
authenticated sequence without weakening the TCP path.

### Handshake retries

The TCP handshake sends one hello and waits for one reply. UDP needs bounded
retries, backoff, and handling of duplicate or late replies.

The current replay filter rejects a repeated client ephemeral key.
Retrying the same hello after a lost response therefore fails. Two options
need evaluation:

- Generate a fresh client ephemeral key for each bounded attempt and retain
  enough client state to match late replies.
- Keep a bounded server reply cache tied to the source and exact hello,
  retransmitting the same reply for a legitimate duplicate.

Neither option establishes source-address ownership or prevents reflection.
Both require rules for discarding duplicate server hellos after session setup.

### Sessions, relay, and backpressure

Today, an accepted TCP socket identifies a session and owns its keys,
sequence counters, and lifecycle. A UDP listener needs an explicit session
table, bounded queues, expiry, and a policy for NAT rebinding.

A source tuple is a cheap index but changes on rebinding. A visible session ID
helps lookup but may be a traffic signature; a sealed ID cannot identify the
decryption key by itself. Scanning many session keys on unknown datagrams
would create a CPU-exhaustion path. Migration needs a bounded lookup design
and return-path validation, not an assumption that it is equivalent to QUIC.

The two-worker TCP relay is not a suitable datagram data path. UDP needs receive
dispatch and routing at both ends. A zero-byte UDP payload is a message, not
EOF, and there is no TCP half-close. Socket creation and some cleanup helpers
can be reused, but connection lifecycle and readiness handling must change.

A UDP design must supply congestion control or an appropriate usage limit,
queue bounds, and an explicit oversized-datagram policy. Fragmentation adds
reassembly state and makes each inner message depend on delivery of all its
fragments. A small inner payload limit may be unsuitable for applications.
Keepalive policy must balance NAT survival, overhead, and visible timing.

### Destinations and SOCKS5

Address encoding and allow-rule checks can be reused. `stream.connect` cannot:
it uses TCP resolution, connection setup, and `TCP_NODELAY`.
A UDP send succeeding does not prove that the destination is reachable.

SOCKS5 UDP ASSOCIATE would additionally require:

1. A TCP control connection whose closure ends the association.
2. A reachable UDP bound address in the reply.
3. Source-address checks for local datagrams and bounded association state.
4. Parsing the UDP request header and an explicit fragmentation policy.
5. Return headers identifying the remote source, plus routing back to the
   correct local application.

These requirements come from
[SOCKS5, RFC 1928 §7](https://www.rfc-editor.org/rfc/rfc1928.html#section-7).
The current CONNECT reply's placeholder bound address is not sufficient for
UDP ASSOCIATE.

### Format policy and CLI

A DNS datagram must be a complete DNS message. Appending the current raw hybrid
body would not satisfy that requirement; `mode_hint` alone cannot enforce a
format-only policy because clients may override it.
The server currently checks hybrid header capacity, not protocol suitability.

Any future transport selector needs a versioned wire contract and explicit URI
parsing/serialization. Unknown URI query keys are currently ignored:
writing `?transport=udp` does not enable UDP. Proposed flags such as
`--transport` or `-U` do not exist.

## Security requirements

A UDP source address can be spoofed. A holder of the connection capability can
create valid hellos, so authenticating `K_cover` alone does not prove return
routability. Before large replies or destination forwarding, the server needs
address validation, such as a reviewed cookie exchange.

Limiting response bytes to request bytes can cap amplification before address
validation, but still permits reflection. A reply cache does not solve this:
an attacker can use fresh hellos. Global work/rate limits are needed before
expensive regex ranking or key exchanges; per-source limits alone can be
bypassed with spoofed sources. Session and retry state must also be bounded.

The TCP rejection delay does not transfer to UDP. Invalid datagrams should
receive no protocol response and should not allocate unbounded state.
The transport's documentation must distinguish this from holding a TCP
connection open before closing it.

Tests need to cover loss, reordering, duplication, spoofed input, forged
sequence numbers, retry storms, rebinding, queue exhaustion, expiry, and
oversized datagrams. Keep the TCP decoder's existing terminal-failure tests.

## Suggested evaluation order

1. **Capacity and semantics:** prototype a UDP DNS message grammar and parser,
   measure payload after all metadata, and decide whether request/reply
   correlation is feasible.
2. **Record model:** test atomic encode/decode, authenticated replay windows,
   and malformed-input drops without sockets.
3. **Minimal transport:** bounded retries, source validation, session expiry,
   queue limits, and a fixed destination. Test under simulated datagram faults.
4. **Integration:** destination policy, migration if justified, SOCKS5 UDP
   ASSOCIATE, CLI, documentation, and a dedicated security review.

Do not schedule this as a minor TCP option. The relay and session model are
substantial new work. Historical timing estimates in earlier drafts predated
the current definitions and lack archived raw runs; measure the proposed UDP
path before using them for capacity planning.
