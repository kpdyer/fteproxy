# fteproxy 0.4: one-argument client, no-argument server

Status: proposal, 2026-09-02. Target release: 0.4.0, which has not been cut yet
(master carries the 0.4.0 preparation; the latest published release is 0.3.2).
Wire format: not compatible with 0.3.x (see Decision D1). Nothing on master's
current wire format has shipped, so there is nothing to preserve.

This plan combines the CLI redesign with the protocol work it depends on. It
is written to be implemented PR by PR, in order; each PR leaves `pytest`
green. Sections 1 through 4 are the design. Section 5 is the PR sequence with
file lists and acceptance checks. Section 6 lists the decisions that need a
maintainer's sign-off before the corresponding PR starts.

## 0. Why the CLI is long today, and what removes the reason

The current command line is long because the operator must keep four things
identical on both endpoints (key, upstream format, downstream format,
record-layer mode) and because each role takes two `ip` + `port` pairs.

The negotiation code already does most of the work to remove this:

- The server accepts any format. It wraps incoming sockets with no format and
  learns the format from the client's first record (`fteproxy/server.py`,
  `NegotiationManager._acceptNegotiation`).
- Formats are a pair by protocol. The client sends the base name and the
  server appends `-request` and `-response` itself
  (`NegotiationManager.doServerSideNegotiation`). Two flags expose a
  combination the wire cannot carry.
- Record-layer mode is the only setting not negotiated. It is a global read
  from config on both sides (`fteproxy._hybrid_mode`).
- The key is the only true shared secret, and it is static and shared by every
  connection and both directions, which is the cross-stream replay limitation
  documented in `SECURITY.md`.

The plan therefore has three parts that only work together:

1. A handshake that authenticates the server with a keypair and derives
   per-connection keys, so the connection string carries a public key instead
   of a shared secret and every other parameter is a client-side choice.
2. In-band destinations, so the server needs no forward address and the client
   can offer SOCKS5. This is what every comparable tool (shadowsocks, chisel,
   wstunnel, hysteria, gost) does.
3. A CLI with two subcommands and one connection string.

Non-goals for 0.4.0: traffic shaping or padding policy, UDP, stream
multiplexing, an asyncio rewrite of the relay, a config file, decoy responses
to failed probes. The record layer's framing, sealing and hybrid body carrier
stay as they are apart from a one-byte record type.

## 1. Target user experience

```
# server, once per host (key is generated on first start)
$ fteproxy server
listening on [::]:8080
key: ~/.local/state/fteproxy/server.key
clients connect with:
  fteproxy client fte://Qm3s…ZzE@<server-ip>:8080
(also written to ~/.local/state/fteproxy/connection.txt)

# client
$ fteproxy client fte://Qm3s…ZzE@203.0.113.5:8080
checking 203.0.113.5:8080 … ok (protocol 1, manual-http, hybrid)
SOCKS5 on 127.0.0.1:1080
$ curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

Same host, no arguments at all: `fteproxy server` then `fteproxy client`. The
client finds `connection.txt` in the state directory.

Port forward instead of SOCKS, ssh syntax:

```
$ fteproxy client fte://… -L 2222:127.0.0.1:22
```

Wrong connection string, old client, or the server is not fteproxy:

```
$ fteproxy client fte://…
checking 203.0.113.5:8080 … failed: no valid handshake reply within 5s
  (wrong connection string, or the server is not running fteproxy 0.4)
exit status 1
```

### 1.1 Command line

```
fteproxy server  [--listen [HOST]:PORT] [--allow RULE]... [--advertise HOST[:PORT]]
                 [--state-dir DIR] [--defs RELEASE] [-q | -v]
fteproxy client  [URI] [-D [BIND:]PORT] [-L [BIND:]PORT:HOST:PORT]...
                 [--format NAME] [--mode hybrid|format] [--no-check]
                 [--state-dir DIR] [-q | -v]
fteproxy keygen  [--state-dir DIR] [--advertise HOST[:PORT]]
fteproxy formats [--defs RELEASE]
fteproxy --version
```

Rules:

- All long flags use hyphens. Ports are integers, validated at parse time.
- `HOST:PORT` everywhere. `:PORT` means all interfaces. IPv6 in brackets.
  `--listen :8080` binds `::` dual-stack where the OS allows it and falls back
  to `0.0.0.0`.
- `server` defaults: listen `:8080`, allow policy per Decision D3, state
  directory per 1.3, definitions release: newest shipped file.
- `client` defaults: SOCKS5 on `127.0.0.1:1080` when neither `-D` nor `-L`
  is given. `-D` is the ssh spelling of `--socks`. `--format manual-http`,
  `--mode hybrid`, unless the URI says otherwise (flags beat the URI).
- The URI may come from the argument, from `FTEPROXY_URI`, or from
  `connection.txt` in the state directory, in that order. A missing URI is a
  usage error with the three sources listed.
- `keygen` creates `server.key` if absent and prints the connection string.
  `server` does the same on first start, so `keygen` exists for provisioning
  (containers, configuration management), not for the manual path.
- `formats` lists every base name in the definitions file with its covertext
  length and capacity, and marks the default.
- A bare `fteproxy` prints usage and exits 2. Every flag of the current command line (`--mode`,
  `--server_ip`, `--client_port`, `--proxy_ip`, `--key`, `--key-file`,
  `--upstream-format`, `--downstream-format`, `--record-layer-mode`,
  `--release`, `--stop`, `--quiet`) is recognised only to print one line
  pointing at the upgrade section of the README and exit 2. No aliases: the
  meaning changed (the destination is now chosen client-side), so a silent
  alias would run a different topology than the operator asked for.
- Exit status: 0 clean shutdown, 1 runtime failure, 2 usage.
- Logs go to stderr through the `logging` module. Default level INFO, `-q`
  ERROR, `-v` DEBUG. The licence banner is gone; `--version` prints it.
- Nothing ever logs a key, a URI, or handshake material. The URI is redacted
  to `fte://…@host:port` in every message.
- `--stop` and the PID files are removed. The process runs in the foreground
  and exits on SIGINT and SIGTERM.

### 1.2 Connection string

```
fte://<server-id>@<host>:<port>[?format=<base>&mode=<hybrid|format>&defs=<YYYYMMDD>]
```

`server-id` is the server's X25519 public key, base64url without padding
(43 characters). `host` is a name, an IPv4 address, or a bracketed IPv6
address. Query parameters are hints the server operator recommends; the client
applies them unless overridden by a flag. Unknown parameters are ignored so
later versions can add some (a `pk2=` for a second key during rotation, for
example).

Treat the string like a Tor bridge line: whoever holds it can connect, and its
secrecy is what stops an active prober from confirming the server. It does
not let the holder impersonate the server or decrypt other clients' traffic
(see 2.4).

### 1.3 State directory

Resolution order: `--state-dir`, `FTEPROXY_STATE_DIR`,
`$XDG_STATE_HOME/fteproxy`, `~/.local/state/fteproxy`. Created with mode
0700. Files:

| File | Mode | Content |
|---|---|---|
| `server.key` | 0600 | 64 hex characters, the X25519 private key |
| `connection.txt` | 0600 | the connection string, one line, `<server-ip>` placeholder unless `--advertise` was given |

The replay filter (2.3) is in memory only.

## 2. Protocol version 1

### 2.1 Keys

- `S` is the server's long-term X25519 keypair. `S_pub` is the server-id.
- `K_cover = HKDF-SHA256(ikm=S_pub, salt=b"", info=b"fteproxy/v1/cover", 32)`.
  Both handshake records are libfte covertexts sealed under `K_cover`. Anyone
  holding the connection string can compute it, which is the intended
  meaning: holding the string is what authorises a connection attempt.
- Per connection: client ephemeral `c`, server ephemeral `s`.
  `DH_ee = X25519(c, s_pub)`, `DH_es = X25519(c, S_pub)` on the client side
  and the corresponding private-key computations on the server. Reject an
  all-zero shared secret.
- `H = SHA-256(b"fteproxy/v1" || S_pub || client_hello_plaintext || s_pub)`.
- `PRK = HKDF-Extract(salt=H, ikm=DH_ee || DH_es)`.
- `K_auth_s, K_c2s_hdr, K_c2s_body, K_s2c_hdr, K_s2c_body =`
  `HKDF-Expand(PRK, info=b"fteproxy/v1/keys", 160)` split into five 32-byte
  keys.

This is the Noise `NK` message pattern (`e, es` then `e, ee`) expressed with
`cryptography`'s X25519, HKDF and HMAC. It gives server authentication and
forward secrecy. It does not authenticate the client beyond possession of the
connection string, the same property obfs4 has. Decision D7 covers whether a
Noise library is used instead; the recommendation is no, because the
maintained options are thin and the pattern is thirty lines.

### 2.2 Handshake records

Both handshake records are sealed exactly as any record is today
(`record_layer._seal`: `len || seq || message || random pad`), in `format`
mode regardless of the mode being negotiated, so the server never has to guess
the mode to read them. `seq` is 0 for the client hello and 0 for the server
hello; the session's data records restart the count per direction (2.4).

Client hello plaintext (sealed under `K_cover` in the `<base>-request`
format):

| Field | Size | Meaning |
|---|---|---|
| version | 1 | `0x01` |
| flags | 1 | bit 0: mode, 0 hybrid, 1 format; other bits must be 0 |
| defs | 4 | definitions release as an integer, e.g. `20260110` |
| format length | 1 | length of the next field |
| format | n | base name, ASCII, e.g. `manual-http` |
| c_pub | 32 | client ephemeral public key |
| epoch | 4 | hours since the Unix epoch, big-endian |

Server hello plaintext (sealed under `K_cover` in the `<base>-response`
format):

| Field | Size | Meaning |
|---|---|---|
| version | 1 | `0x01` |
| flags | 1 | echo of the accepted mode bit |
| s_pub | 32 | server ephemeral public key |
| mac | 16 | `HMAC-SHA256(K_auth_s, H)[:16]` |

The server proves possession of `S` by producing `mac`, because `PRK`
depends on `DH_es`. The server hello is the acknowledgement the current negotiation lacks: on receiving a valid one the client knows the key, format, mode and
version all match, before any application byte is sent.

Every shipped format must hold a client hello (about 75 bytes plus libfte's
28-byte AE frame) in one covertext. PR2 adds a definitions-load check that
fails on any format whose capacity is below 128 bytes, and adjusts `length`
in the definitions file for any that fail.

### 2.3 Server behaviour on the first record

1. Buffer until at least the largest request-format covertext could be
   present, then try to unseal the buffered bytes under `K_cover` with each
   request format, most-recently-matched first. This replaces the configured
   `--upstream-format` hint with an adaptive order and keeps the existing
   cipher cache (one static key per server, so `_make_cipher` hits).
2. Reject if: version unknown, reserved flag bits set, `defs` is not the
   release the server serves, format unknown, epoch outside ±1 hour, or
   `c_pub` seen within the window (replay filter keyed on `c_pub`, pruned by
   epoch).
3. On rejection: never reply. Read and discard for a random 1 to 5 seconds,
   then close. Log one line at DEBUG. This is obfs4's behaviour and is what
   stops an active prober learning anything from a bad guess.
4. On success: derive keys, send the server hello, switch to session ciphers.

### 2.4 Session records

After the handshake, each direction has its own header key and body key and
its own `seq` starting at 0. The FTE header cipher for a session is built as
`fte.FTE(output_format=<cached RegexFormat>, key=K_dir_hdr)`: PR2 splits the
current `_make_cipher` cache so that `RegexFormat` (the DFA, the expensive
part) is cached by `(pattern, length)` and the `FTE` instance is built per
session with the session key. The body carrier `_AEADBody` is built per
session with `K_dir_body`. Per-connection keys close the cross-stream replay
limitation in `SECURITY.md` and give forward secrecy.

Record plaintext gains a leading type byte:

| Type | Name | Payload |
|---|---|---|
| `0x00` | DATA | application bytes |
| `0x01` | OPEN | destination, see 3.1 |
| `0x02` | OPEN_RESULT | status, see 3.1 |
| `0x03` | PADDING | ignored; reserved for future shaping |
| `0x04` | CLOSE | no payload; the sender will send no more DATA |

Unknown types close the connection. In `hybrid` mode the type byte is the
first byte of the raw body; in `format` mode it is the first byte inside the
sealed covertext. The sealed length and `seq` fields are unchanged, so the
record layer's chunking, buffering and bounds logic is unchanged.

Headers in `hybrid` mode are sealed under the session header key, so a
connection-string holder can no longer forge a header for someone else's
stream, which was the remaining gap when a cover key was considered for
headers.

### 2.5 What an observer sees

Unchanged from the current record layer for data records. The two handshake records are one
request-format covertext and one response-format covertext, the same shape as today's negotiation cell and its first reply. A prober without the connection
string gets no bytes back.

## 3. Streams and destinations

### 3.1 OPEN and OPEN_RESULT

OPEN payload, SOCKS5 address encoding so the client can pass a SOCKS request
through without re-encoding:

| Field | Size | Meaning |
|---|---|---|
| atyp | 1 | `0x01` IPv4, `0x03` domain name, `0x04` IPv6 |
| addr | 4, 1+n, or 16 | address or length-prefixed name |
| port | 2 | big-endian |

OPEN_RESULT payload: one status byte using SOCKS5 reply codes (`0x00`
succeeded, `0x01` general failure, `0x02` not allowed by ruleset, `0x03`
network unreachable, `0x04` host unreachable, `0x05` connection refused,
`0x06` TTL expired). The client maps it straight onto its SOCKS5 reply.

OPEN is a relay-layer message. The library API (3.4) lets a program send DATA
without ever sending OPEN, which is what the chat and echo examples do.

### 3.2 Server

The accept loop hands each connection to a setup thread immediately; today
it dials the fixed destination inside the accept loop, so a slow `connect()`
stalls every other client. The setup thread: handshake (2.3), read OPEN with
the negotiation timeout, check the allow rules, dial with a 10-second timeout,
send OPEN_RESULT, then start the two relay workers as today. Any failure after
the handshake sends OPEN_RESULT with the matching status and closes.

Allow rules, `--allow RULE`, repeatable:

- `any`: everything.
- `HOST[:PORT]`, `CIDR[:PORT]`, `*.example.com[:PORT]`: as written; a rule
  without a port allows every port. Names are matched against the requested
  name; a request by IP is matched against IP and CIDR rules only.
- Default (Decision D3): all destinations except the server's loopback and
  link-local ranges. `--allow 127.0.0.1:8081` opts a local service back in.

The server resolves names itself, so a `-L` forward to `127.0.0.1:22` means
port 22 on the server host, which is exactly what the current topology does with
`--proxy_ip 127.0.0.1`.

### 3.3 Client

Two listener kinds, any number of each:

- `-D [BIND:]PORT`: SOCKS5, RFC 1928, CONNECT only, no authentication
  method, IPv4, IPv6 and domain address types. UDP ASSOCIATE and BIND return
  `0x07` command not supported.
- `-L [BIND:]PORT:HOST:PORT`: plain listener; every accepted connection opens
  `HOST:PORT` through the tunnel.

Per accepted connection: dial the server, handshake, send OPEN, wait for
OPEN_RESULT, then (SOCKS only) send the SOCKS reply, then relay. Local bytes
that arrive before OPEN_RESULT are buffered, bounded by the relay's existing
receive buffer size.

Startup check (Decision D5): unless `--no-check`, the client dials the server
once, completes the handshake, and closes. Success prints one line with the
protocol version, format and mode; failure prints the reason and exits 1. The
check is one short connection that looks like any other session start.

### 3.4 Library API

`fteproxy.wrap_socket` keeps its name and gains a role from its keyword
arguments; `K1`, `K2` and `negotiate` are removed.

```python
# server side
sock = fteproxy.wrap_socket(conn, server_key=private_key_bytes)
dest = sock.wait_open()            # (host, port) or None if the peer sent DATA first
sock.open_result(0x00)

# client side
sock = fteproxy.wrap_socket(raw, server_id=public_key_bytes_or_str,
                            format="manual-http", mode="hybrid")
sock.open(("example.com", 443))     # raises fteproxy.OpenRefused(status) on failure
```

`fteproxy.generate_server_key()` returns `(private_bytes, public_bytes)`;
`fteproxy.ConnectionString.parse(str)` and `.format()` round-trip the URI.
Handshake and key-schedule code lives in a new `fteproxy/handshake.py`;
stream messages and allow rules in `fteproxy/stream.py`; SOCKS5 in
`fteproxy/socks.py`; URI and state directory in `fteproxy/config.py`.

## 4. Documentation and security model

- `README.md`: rewrite Usage around the two commands and the connection
  string; replace the options table; rewrite "Upgrading to 0.4.0" to cover the wire break from 0.3.x, the new
  command line, keys, the topology change, and `-L` for the old
  fixed-destination setup. `PYPI_README.md` mirrors the quick start.
- `SECURITY.md`: replace "The key" with the keypair and connection-string
  model; delete the cross-stream replay limitation and "No protocol-version
  handshake"; add: what the connection string authorises, replay window and
  filter, behaviour on failed handshakes, the allow-rule default, and that
  the handshake is Noise-NK-shaped and hand-assembled from `cryptography`
  primitives with test vectors in the repository.
- `examples/`: the shell scripts become two-line invocations; Python examples
  use `generate_server_key` and the new `wrap_socket`; `examples/README.md`
  and the per-directory READMEs updated. `benchmark.py` and
  `fteproxy/tests/test_system.py` move to the new command line.

## 5. PR sequence

Each PR is independently mergeable and leaves the test suite green. Sizes:
S under 300 lines changed, M under 800, L above.

### PR1 (S): parser hygiene and the bugs found on the way

No user-visible flag changes.

- Replace the `setConfValue` argparse action with a plain parse followed by
  one `apply_args_to_conf` step; `type=int` on ports; delete the dead
  `--stop`/`--mode` guards.
- Fix: no-argument run crashes with a `TypeError` and exits 0 (default mode
  never reaches config because argparse does not run actions for defaults).
- Fix: invalid format name and other startup failures exit 0.
- Validate formats and key before printing anything or writing the PID file.
- `logging` to stderr with `-q`/`-v`; `warn`/`info`/`fatal_error` become
  thin wrappers; exit codes 0/1/2.
- `fteproxy formats` subcommand (argparse subparsers introduced here, with the
  existing flat interface kept as the default command).
- Tests: `tests/test_cli.py` for parse and apply; system test for the
  no-argument case and exit codes.

Acceptance: `python -m fteproxy` prints usage and exits 2;
`python -m fteproxy --mode client --upstream-format nope; echo $?` prints 1;
`pytest` green.

### PR2 (L): handshake, session keys, record types

Wire break from 0.3.x; the version stays 0.4.0 because 0.4.0 has not been
cut. Library level only.

- `fteproxy/handshake.py`: key generation, `K_cover`, hello encode/decode,
  key schedule, epoch, replay filter. Test vectors generated once and checked
  in (`tests/vectors/handshake_v1.json`).
- `fteproxy/__init__.py`: split the cipher cache into a `RegexFormat` cache
  and per-session `FTE` construction; per-direction `_AEADBody`; record type
  byte in `record_layer`; `NegotiationManager` replaced by the handshake
  driver; `wrap_socket` new signature; `generate_server_key`.
- Definitions-load capacity check (2.2); adjust any format that cannot hold
  a hello.
- Server-side first-record scan with most-recently-matched ordering and the
  reject path (2.3).
- Tests: vectors; tamper each field of each hello; replay within and outside
  the window; epoch skew; wrong `S_pub`; each record type; both modes;
  `benchmark.py` before/after for the per-session cipher construction cost
  (target: connection setup within 1 ms of 0.4, bulk throughput unchanged).
- Review gate: a security review of `handshake.py` and the key schedule by
  someone other than the author before merge, as was done for #229.

Acceptance: `pytest fteproxy/tests/test_handshake.py test_record_layer.py
test_socket_wrapper.py`; a client speaking master's pre-plan negotiation against the new server produces no reply and one DEBUG log line.

### PR3 (L): streams, SOCKS5, allow rules, relay rewrite

- `fteproxy/stream.py`: OPEN/OPEN_RESULT encode/decode, allow rules, address
  classification (loopback, link-local).
- `fteproxy/socks.py`: RFC 1928 CONNECT server side for the client listener.
- `fteproxy/relay.py`: per-connection setup thread on the server; listener
  kinds on the client; OPEN before relay; half-close via CLOSE where the
  local socket supports `shutdown(SHUT_WR)`; workers unchanged otherwise.
- `fteproxy/server.py` and `client.py` collapse into the new relay roles.
- Tests: allow-rule table; SOCKS5 conformance against a local echo server
  including each failure reply; `-L` flow; OPEN to a refused port maps to
  `0x05`; default policy blocks `127.0.0.1` and `--allow` re-enables it.

Acceptance: end-to-end SOCKS transfer and `-L` transfer in
`test_system.py` using the library API directly (the CLI lands in PR4).

### PR4 (M): the command line

- `fteproxy/config.py`: connection string parse/format, state directory,
  `server.key` and `connection.txt` handling with the modes in 1.3.
- `fteproxy/cli.py`: `server`, `client`, `keygen`, `formats` subparsers as
  in 1.1; `HOST:PORT` and `-L` spec parsers with IPv6 brackets; dual-stack
  bind; startup check; old-flag error; env vars; redaction filter on the
  logger; signal handling; removal of PID files and `--stop`.
- `benchmark.py` and `test_system.py` on the new command line.
- Tests: URI round-trips including IPv6 and query hints; spec parsers;
  state-directory permissions; old flags exit 2 with the pointer; startup
  check pass and fail; no-argument client finds `connection.txt`.

Acceptance: the transcript in section 1 works verbatim on one host, with the
`curl` line pointed at a local HTTP server and `--allow 127.0.0.1:PORT` on
the server.

### PR5 (M): docs, examples, release

- Section 4 in full. `__version__` stays `"0.4.0"`; PyPI metadata; the
  `SECURITY.md` supported-versions table already lists 0.4.x.
- `examples/` scripts and Python files; `test_examples.py`.
- Release notes: wire break, command-line change, topology change, key
  model, upgrade steps.

Acceptance: `pytest` green including `test_examples.py`; README quick start
executed by hand on two hosts.

## 6. Decisions needed

Each has a recommendation; the PR that depends on it is noted.

- **D1 (PR2)** No compatibility path for the shared-key negotiation on master or for the 0.3.x wire format.
  Recommended: yes. A compatibility mode would keep the shared-key path and
  its public default key alive and double the first-record scan.
- **D2 (PR2)** Remove shared-key operation entirely (`--key`, `--key-file`,
  `negotiate=False`). Recommended: yes. One key model is easier to explain
  and audit; the examples that used the symmetric mode move to the keypair.
- **D3 (PR3)** Default destination policy: block the server's loopback and
  link-local unless allowed. Recommended: yes. The alternative (allow all,
  as shadowsocks does) exposes every local admin service to every holder of
  the connection string.
- **D4 (PR3)** Client default listener: SOCKS5 on `127.0.0.1:1080`.
  Recommended: yes; matches shadowsocks, hysteria and wstunnel defaults.
- **D5 (PR4)** Startup check on by default, `--no-check` to skip.
  Recommended: yes. The cost is one short connection; the benefit is that a
  bad connection string fails in one second with a reason instead of a
  timeout on first use.
- **D6 (PR4)** Scheme name `fte://`, base64url server-id, state directory
  under `$XDG_STATE_HOME`. Recommended as written.
- **D7 (PR2)** Hand-assemble the NK handshake from `cryptography` primitives
  with checked-in vectors and an external review, rather than add a Noise
  dependency. Recommended: yes; the candidate libraries are unmaintained and
  the pattern is small.
