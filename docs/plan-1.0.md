# fteproxy 1.0 design history

The original plan was written on 2026-09-02. Its handshake, destination
protocol, and CLI redesign are implemented in this checkout.
This is an architectural record, not a release announcement or a pending
execution plan. For current commands, use the [README](../README.md).

## Decisions implemented

| Area | Result |
|---|---|
| Compatibility | Wire break from 0.3.x; no legacy shared-key negotiation |
| Identity | Long-term server X25519 keypair; clients receive a connection capability |
| Session keys | Ephemeral exchanges derive header/body keys for each direction |
| Destinations | Client sends OPEN; server applies allow rules and returns OPEN_RESULT |
| Local access | SOCKS5 CONNECT and repeatable fixed forwards |
| CLI | `server`, `client`, `keygen`, `formats`, `defs-check`, `version`, `help` |
| Startup | Foreground processes, handshake check by default, exit statuses 0/1/2 |
| Lifecycle | Two relay workers after setup; CLOSE supports half-close |

UDP, multiplexing, automatic traffic shaping, a configuration-file format, and
an event-loop rewrite were outside this redesign. UDP remains a
[feasibility study](udp-feasibility.md).

## Protocol v1

Both hellos are sealed FTE covertexts under a key derived from the server's
public key. This makes possession of the connection URI sufficient to initiate
a handshake. The server's private key is still required to authenticate its
reply. The exchange follows the key-exchange structure of Noise NK with a
fteproxy-specific transcript and key schedule.

All multibyte integers below are big-endian.

| Client hello field | Bytes |
|---|---:|
| Version, `0x01` | 1 |
| Flags: bit 0 selects format mode; other bits zero | 1 |
| Definitions release as an integer | 4 |
| ASCII base-name length | 1 |
| Base name | n |
| Client ephemeral public key | 32 |
| Epoch in hours since Unix epoch | 4 |

| Server hello field | Bytes |
|---|---:|
| Version | 1 |
| Accepted mode flags | 1 |
| Server ephemeral public key | 32 |
| Server authentication MAC | 16 |

The client hello is `43 + n` bytes; the server hello is 50 bytes.
Both also need the 12-byte seal. Handshakes use the format's maximum wire
length and sequence zero. Session records restart sequencing at zero under
new per-direction keys. See [SECURITY.md](../SECURITY.md) and
[handshake.py](../fteproxy/handshake.py) for the key schedule and replay limits.

## Stream records

| Type | Name | Payload |
|---|---|---|
| `0x00` | DATA | Application bytes |
| `0x01` | OPEN | SOCKS5-encoded address and port |
| `0x02` | OPEN_RESULT | One SOCKS5-style status byte |
| `0x03` | PADDING | Ignored on receipt |
| `0x04` | CLOSE | Sender has finished sending DATA |

OPEN is required by the relay, but programs using wrapped sockets directly
may exchange DATA without it. The server resolves requested names and checks
each destination before connecting. The client maps OPEN_RESULT onto a SOCKS
reply or closes a refused fixed forward.

## Refinements after the original proposal

The implementation is stricter than several early examples in the plan:

- The default destination policy permits only globally routable unicast
  addresses. `--allow any` does not permit private destinations without an
  explicit IP/CIDR rule.
- A normal server start stores its URI in `connection.txt` without printing
  it. File/stdin input is preferred, and new files contain usable addresses
  rather than `<server-ip>` placeholders.
- Local listeners require literal loopback binds unless
  `--expose-listeners` is set.
- Setup and established-session concurrency have global and per-source limits.
- Definitions are retained per connection, while the format and mode are
  selected by the client. Both peers must have matching definitions.
- Release `20260903` and `http` replaced the old shape defaults. Variable
  format-mode lengths and HTTP chunk framing are documented in
  [format design history](plan-formats.md).
- Rejection deadlines include the handshake timeout and are anchored near
  accept time; a failed check is not guaranteed to return in one round trip.

## Implementation map

| File | Responsibility |
|---|---|
| [handshake.py](../fteproxy/handshake.py) | Hello encoding, key schedule, epoch and replay filter |
| [record_layer.py](../fteproxy/record_layer.py) | Seals, typed records, framing and sequence checks |
| [__init__.py](../fteproxy/__init__.py) | Socket handshake driver, cipher caches and wrapper API |
| [stream.py](../fteproxy/stream.py) | Addresses, destination policy and dialing |
| [socks.py](../fteproxy/socks.py) | Local SOCKS5 method selection, requests and replies |
| [relay.py](../fteproxy/relay.py) | Admission, setup threads, forwarding and teardown |
| [config.py](../fteproxy/config.py) | URI parsing and private state files |
| [cli.py](../fteproxy/cli.py) | Commands, startup checks, logging and shutdown |
