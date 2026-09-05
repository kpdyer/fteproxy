# Security policy

## Supported versions

Security fixes target the latest release line.

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| Earlier versions | No |

## Scope

fteproxy encrypts TCP streams and formats their wire records to target
signature and keyword filters. It does not provide anonymity, hide traffic
timing or volume, or make traffic indistinguishable from a real application
protocol. UDP, stream multiplexing, and automatic traffic shaping are not
implemented.

Encryption covers the fteproxy client-to-server hop. Applications need their
own end-to-end protection, such as TLS or SSH, for traffic beyond the server.
See also [libfte's security model](https://github.com/kpdyer/libfte/blob/master/SECURITY.md).

## Server identity and connection capability

The server holds a long-term X25519 private key in `server.key`.
The URI `fte://SERVER-ID@HOST:PORT` carries its public key as the server ID.
Clients need no server private key or shared symmetric key.

The public key is nevertheless a connection capability:
`K_cover = HKDF-SHA256(S_pub, salt=b"", info=b"fteproxy/v1/cover", length=32)`
seals both handshake records. Anyone with the URI can compute this key,
initiate connections, and decode captured handshake metadata. Protect the URI
like a secret. Possessing it does not by itself let a holder impersonate the
server or decrypt another client's session data.

Prefer `client --connection-file`, `--connection-stdin`, or the implicit
state file. A positional URI can appear in process listings, shell history,
and diagnostic output. A normal server start stores the URI without printing
it; `server --print-connection` and `keygen` explicitly print it.

New state directories use mode 0700; new key and connection files use mode
0600. Existing state directories must be owned by the current user where
ownership checks are available, must not be symlinks, and must not grant group
or other permissions. Managed reads reject symlinks, hard links, non-regular
files, and foreign ownership. Loose file permissions warn rather than reject.
Explicit connection files also warn about unexpected ownership.
Writes publish complete sibling files atomically without following a symlink
at the target. These checks do not replace protection of parent directories
or platform-specific access controls.

If an identity or connection capability is exposed, create a new server
identity and redistribute its connection file. Restarting with the same
`server.key` does not revoke existing capabilities. A legacy
`<server-ip>` placeholder is translated to loopback only when read implicitly
from the same host's state file; explicit inputs reject it.

## Handshake and session keys

Protocol v1 uses X25519, HKDF-SHA256, and HMAC-SHA256. Its key exchanges follow
the `e, es` / `e, ee` structure of Noise NK, but its transcript, framing,
and key schedule are fteproxy-specific; it is not a standard Noise wire
implementation. See the [Noise framework](https://noiseprotocol.org/noise.html).

Each endpoint generates an ephemeral key. The transcript hash is:

```text
H = SHA-256("fteproxy/v1" || S_pub || client_hello_bytes || s_pub)
```

HKDF derives five 32-byte keys from `DH_ee || DH_es`, with `H` as salt:
one server authentication key and a header/body key pair for each direction.
The server proves its identity with `HMAC-SHA256(K_auth_s, H)[:16]`.
The client checks the reply's version and mode as well as this MAC.
All-zero X25519 shared secrets are rejected.

Fresh ephemeral keys provide forward secrecy for recorded session data if the
long-term server key is later compromised. Clients are authorized by capability
possession; the protocol does not assign or authenticate individual client
identities. Test vectors in
[handshake_v1.json](fteproxy/tests/vectors/handshake_v1.json) pin the wire
encoding and key schedule; tests are not a substitute for cryptographic review.

## Records, ordering, and replay

FTE covertexts use libfte's authenticated encryption. Hybrid bodies use
AES-128-CTR followed by HMAC-SHA256 with a 16-byte tag and a 12-byte random
nonce. Encryption and MAC subkeys are derived separately.

Each direction has its own session keys and sequence counter starting at zero.
The covertext seal includes the sequence number; hybrid body tags bind it too.
Replayed or reordered records fail, and a missing record is detected when a
later sequence number arrives. Unknown record types, invalid framing, or failed
authentication stop decoding. Transport EOF alone does not prove that the peer
delivered its complete intended stream; applications should verify completion.

Client hellos carry an epoch measured in hours and are accepted within ±1 of
the server's current epoch. A process-wide replay filter remembers client
ephemeral public keys in epoch buckets, capped at 131,072 entries.
It removes entries from the fullest bucket when over capacity. This bounds
memory, but entries in that bucket can be evicted; a flood of valid hellos can
therefore re-enable replay within the accepted window. Restarting the process
also clears the filter.

The filter runs after hello syntax, release, format-name, and epoch checks,
but before the X25519 exchanges and later socket-level checks. A hello can
consume an entry even if a later check rejects it.

## Handshake rejection and resource limits

An admitted connection with an invalid hello receives no protocol reply.
The server reads and discards until the handshake deadline plus a random
1–5 seconds, measured from socket wrapping (near accept time), then closes.
With the default five-second timeout this targets a 6–10 second lifetime.
Peer closure, I/O errors, shutdown, or scheduling delays can alter that timing;
this is not a guarantee that the service is unidentifiable.

A silent peer occupies a setup slot during the wait. Limits bound that work:

| Resource | Global default | Per-source-IP default |
|---|---:|---:|
| Server handshake/OPEN setup | 64 | 8 |
| Established server relays | 128 | 64 |
| Client SOCKS/forward setup, across listeners | 32 | 16 |

Excess setup connections close immediately without another setup thread.
A destination is dialed before established-session admission; if that limit is
full, the server closes the destination and sends a general-failure OPEN result.
The limits bound concurrency, not connection rates, DNS resolver latency, or
idle-session duration.

First-record scanning tries each eligible request format at most once per
connection, with the most recently matched format first. A five-second
handshake timeout and a 64 KiB pre-handshake threshold limit input handling.
The threshold is checked between reads, so a read can temporarily exceed it.
Compilation and Python scheduling are not interrupted by that timeout.

## Destination and listener policy

With no allow rules, the server dials only globally routable unicast addresses,
using Python's IP address classification and explicit exclusions for private,
shared, loopback, link-local, reserved, unspecified, and multicast space.
IPv4-mapped IPv6 addresses are classified as IPv4.

Explicit `--allow` rules replace the default with an allowlist. Hostname
patterns and `any` still require a globally routable result. Only a matching
IP/CIDR rule permits a non-global destination, including a hostname resolving
there. The server checks each resolved candidate and connects to the checked
numeric address, avoiding a second DNS lookup at connect time.

SOCKS5 supports CONNECT with no authentication, using IPv4, IPv6, or a domain
name. BIND and UDP ASSOCIATE are refused. The CLI requires literal loopback
binds unless `--expose-listeners` is set; the Python listener API does not
enforce that CLI policy. Anyone who reaches a local listener can use it.

Destination names sent through SOCKS or OPEN are resolved by the server.
Applications that resolve before proxying, and the client's lookup of the
fteproxy server itself, can still use local DNS.

## What observers can distinguish

- **Hybrid bodies remain high entropy.** Their length is application payload
  plus 29 bytes (type, nonce, and tag), before carrier framing. HTTP adds
  `len(format(B, "x")) + 9` framing bytes around a non-empty encrypted body
  of `B` bytes. Other carriers append the body directly, which can violate
  the apparent protocol's message framing, especially DNS over TCP.
- **Lengths remain distinctive.** Current format-mode records choose among
  eight lengths; this is not a measured protocol length distribution.
  Handshakes use maximum-length covertexts, and hybrid headers use one fixed
  length per direction.
- **Field values are artificial.** Padding fills the available plaintext
  capacity before encryption, avoiding the systematic low-rank prefixes of
  short unpadded messages. It does not generate plausible URLs, hostnames,
  SIP fields, or natural language. Regex alternatives can be heavily biased.
- **Messages are independent.** Request and response counts, timing, IDs, and
  fields are not correlated. DNS responses are not constructed to echo query
  IDs and questions. HTTP responses need not correspond to requests.
  Parsing individual records does not validate a protocol conversation.

HTTP's base grammar produces zero-body handshake and format-mode messages.
Its hybrid grammar produces POST requests and body-permitted responses with
chunked bodies. It requires a direct TCP path that preserves bytes:
header rewriting or dechunking/rechunking can invalidate records.
It is not an HTTP proxy transport.

Definitions are trusted local input. A peer may select a packaged format but
cannot provide a regex or length range. Complex patterns can make compilation
expensive; do not install untrusted definition files.

## Logging

The package logger redacts URI authority credentials, hex strings of at least
32 characters, and bare 43-character base64url tokens. Parser diagnostics also
redact URI-shaped arguments. These are pattern-based safeguards, not a general
secret detector; callers must not log keys or handshake material.
Endpoints and destination metadata may still appear in logs.

## Report a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/kpdyer/fteproxy/security/advisories/new),
rather than public issues, pull requests, or discussions.

Include affected versions, impact, reproduction steps or a proof of concept,
and any suggested fix. We aim to acknowledge reports within seven days,
provide progress updates, and coordinate disclosure and credit unless you
prefer anonymity.
