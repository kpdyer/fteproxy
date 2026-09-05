# fteproxy 1.0.0

1.0.0 replaces the protocol, the command line and the topology together,
because none of the three worked without the other two. The short version: a
server needs no arguments, a client needs a connection source, and there is no
shared secret.

```console
$ fteproxy server --advertise vpn.example.com:8080
listening on [::]:8080
key: ~/.local/state/fteproxy/server.key (created)
allowing: globally routable unicast destinations
connection string written to ~/.local/state/fteproxy/connection.txt

$ fteproxy client --connection-file ./connection.txt
checking vpn.example.com:8080 ... ok (protocol 1, http, hybrid)
SOCKS5 on 127.0.0.1:1080
```

## Breaking changes

**The wire format changed and there is no compatibility mode.** A 0.3.x peer,
or a peer running an earlier development build, gets no reply at all —
which is the same thing an active prober gets, deliberately. Upgrade both ends
together.

**The command line changed.** Every flag of the old one — `--mode`,
`--server_ip`, `--server_port`, `--client_ip`, `--client_port`, `--proxy_ip`,
`--proxy_port`, `--key`, `--key-file`, `--upstream-format`,
`--downstream-format`, `--record-layer-mode`, `--release`, `--stop`,
`--quiet` — is recognised only to print a pointer to the upgrade notes and
exit 2. None of them is aliased: the meaning changed rather than the spelling,
so a silent alias would run a different topology than the operator asked for.

**The destination is chosen on the client.** The server has no forward
address; the client sends the destination in band, so one server serves SOCKS5
clients and port forwards at once and never needs reconfiguring for a new
destination. `--proxy_ip`/`--proxy_port` have no server-side equivalent.

**There is no shared key.** `--key` and `--key-file` are gone, and so is the
public default key that used to stand in for them.

**PID files and `--stop` are gone.** The process runs in the foreground and
exits on SIGINT or SIGTERM.

## What is new

- **A server keypair and a connection string.** The server generates an
  X25519 keypair on first start into `~/.local/state/fteproxy/server.key`
  (mode 0600, in a directory with mode 0700), then writes the mode-0600
  `connection.txt` alongside. A normal server start does not print this
  capability; `--print-connection` is the explicit stdout opt-in.
  `--advertise` supplies the remote address. Without it, an existing endpoint
  for the same identity is preserved; new invitations use a valid local address
  rather than an editable `<server-ip>` placeholder.
  `fteproxy keygen` does the same without starting a server and prints the URI
  because producing it is that command's purpose. A client holds only the
  public half.
- **Protocol version 1: a real handshake.** The Noise `NK` pattern
  (`e, es` then `e, ee`) over X25519, HKDF-SHA256 and HMAC-SHA256, giving
  server authentication, forward secrecy, and a separate header key and body
  key for each direction of each connection. That closes the cross-stream
  replay limitation the shared-key line documented. Both handshake records are
  ordinary covertexts, so the shape on the wire is unchanged.
- **A failed handshake is answered with silence.** Wrong key, wrong format,
  stale clock, replayed hello: all identical from outside — no reply, read and
  discard, then close a random 1 to 5 seconds after the handshake timeout,
  timed from the accept so that when the check failed does not show. A replay
  filter keyed on the client's ephemeral key covers the ±1 hour epoch window.
- **Capability-safe client input.** `--connection-file FILE` and
  `--connection-stdin` keep the connection URI out of process argv. The
  positional URI and `$FTEPROXY_URI` remain compatible fallbacks, but files,
  stdin and the implicit state `connection.txt` are preferred. Explicit
  sources are mutually exclusive, and parser errors redact URI-shaped input.
  A legacy `<server-ip>` maps to loopback only when read implicitly from the
  same host's state file; explicit inputs must contain a real address.
- **SOCKS5 and ssh-style forwards.** `-D`/`--socks-listen [BIND:]PORT` is a
  SOCKS5 CONNECT listener (the default is `127.0.0.1:1080`);
  `-L`/`--forward [BIND:]PORT:HOST:PORT` is a fixed forward. Both are
  repeatable and can be mixed. Names are resolved at the far end, so client
  DNS does not leak around the tunnel. Because the listeners have no client
  authentication, a non-loopback bind is rejected unless
  `--expose-listeners` explicitly opts in.
- **`--allow` rules on the server.** With no rules, only globally routable
  unicast addresses are reachable, checked on the request *and* on every
  resolved address. One or more rules form a whitelist. A hostname rule and
  `--allow any` still require a global result; only an explicit IP/CIDR rule
  opts a private or other non-global address in. For example,
  `--allow 127.0.0.1:8081` publishes exactly one local service.
- **A startup check.** After validating and binding its local listeners, the
  client opens one short session and prints
  `checking HOST:PORT ... ok (protocol 1, format, mode)`, or a reason and exit
  1. `--no-check` skips it.
- **Format and mode are negotiated.** One `--format` base name on the client
  replaces the two format flags, and `--mode` replaces `--record-layer-mode` on
  one side only. A mismatch between endpoints is no longer possible.
  `fteproxy formats` lists the base names with the capacity of one covertext.
- **Half-close.** A stream that ends in one direction now says so, instead of
  tearing down both, so an HTTP request that finishes while its response is
  still arriving works.
- **Failures are visible.** Exit status is 0 clean / 1 runtime failure /
  2 usage; a no-argument run prints usage instead of crashing with a
  `TypeError` and exiting 0; an unknown format, an unreadable key and a refused
  bind all report themselves instead of exiting 0.
- **Logging.** stderr through the `logging` module, `-q` for errors only and
  `-v` for per-connection detail, with a redaction filter that keeps a key, a
  server-id or a connection string out of any log line. The connection URI
  reaches stdout only for `keygen` or explicit `server --print-connection`;
  ordinary output such as the format table remains pipeable.
- **A strict CLI.** `server`, `client`, `keygen`, `formats`, and
  `defs-check` reject abbreviated long options and unsafe definitions
  identifiers. Address, rule and definitions validation happens before a key
  or state file is created or a peer is contacted. An existing state directory
  with permissions broader than 0700 is refused rather than silently changed;
  fix an intended directory explicitly with `chmod 700`. Managed key and
  invitation reads reject symlinks, hard links, non-regular files, and foreign
  ownership. Actions use plain commands: `fteproxy help` lists commands,
  `fteproxy help COMMAND` shows their options, and `fteproxy version` prints
  the version and licence.

## Upgrade steps

1. Upgrade both endpoints to 1.0.0 at the same time. There is no window in
   which a 0.3 client and a 1.0 server interoperate.
2. Start the server once and keep the connection file it creates:

   ```bash
   fteproxy server --advertise your.host:8080
   ```

   Choose any `--allow` rules deliberately. The new default reaches only
   globally routable unicast destinations, which is narrower than 0.3. An
   explicit IP/CIDR rule is required for a private service.
3. Securely copy the mode-0600 `connection.txt` to each client, and translate
   the old fixed-destination setup into a `-L` forward:

   ```bash
   # 0.3
   fteproxy --mode client --client_port 8079 --server_ip S --server_port 8080
   # 1.0, with the server's --proxy_ip:--proxy_port as the -L destination
   fteproxy client --connection-file ./connection.txt \
     --forward 8079:127.0.0.1:22
   ```

   Or drop the forward and let applications use SOCKS5 on `127.0.0.1:1080`.
4. Delete the old shared key file; nothing reads it any more.
5. If you embedded fteproxy: `wrap_socket`'s `outgoing_regex`, `incoming_regex`,
   `K1`, `K2` and `negotiate` parameters are replaced by `server_key=` (server
   role) or `server_id=` plus `format=`/`mode=` (client role), with
   `generate_server_key()`, `sock.open()`, `sock.wait_open()` and
   `sock.open_result()` alongside. See the README's Python API section and
   `examples/`.

## Definitions

The shipped release is `20260903`: five real cleartext protocols, a request and
a response format each -- `http` (ports 80/8080/8000, hybrid), `ftp` (21),
`smtp` (25/587), `sip` (5060) and `dns` over TCP (53), the last four in format
mode. `http` is the default format, and a client given neither `--format` nor a
`?format=` hint picks the format whose protocol runs on the server's port,
falling back to `http`.

No format emits every covertext at one length any more. In `format` mode each
record picks a covertext length from across the format's range -- `http`
200–700 bytes, `sip` 300–800, `smtp` 80–320, `ftp` 64–256, `dns` 90–272 -- so a
capture shows a spread of message sizes instead of one repeated size, and the
choice leans short for interactive traffic and long for bulk. The four text
formats are framed by a terminator (`\r\n\r\n`, or `\r\n` for the line
protocols) rather than by a fixed slice. `dns` is framed by the two-byte
big-endian length prefix RFC 1035 puts in front of every DNS-over-TCP message:
that prefix is framing rather than part of the format's regex, so one pattern
serves all eight of its lengths, and a `dns` query name now runs 72–254 octets
instead of padding to 254 every time. Two things stay fixed length. The two
handshake records are always at the top of the format's range, because the
server has to frame a client hello before it can decrypt anything. A `hybrid`
mode header is fixed too, but at the *shortest* length the format can hold one
in — 200 bytes for `http` rather than 700, 80 for `smtp`, 90 for `dns` — since
its sealed payload carries only the four-byte length of the authenticated body
behind it, excluding carrier framing. `fteproxy formats` shows the length per
format in its `hdr` column.

HTTP now has two header grammars. Handshake records and `format` mode keep the
base zero-body grammar: the response is a header-block-only 200/302/304/404
message with `Content-Length: 0`. (`http-response` lost its old body field
because a field admitting CRLF CRLF would break terminator framing.)
Post-handshake `hybrid` records use a separate grammar: requests are `POST`,
requests and responses advertise `Transfer-Encoding: chunked`, and responses
exclude body-forbidden `304`. The record layer sends the authenticated
ciphertext as exactly one chunk followed by the terminal zero chunk. A
non-empty encrypted body of `B` bytes therefore has
`len(format(B, "x")) + 9` bytes of visible HTTP chunk framing. This corrects
the earlier invalid layout, which
appended ciphertext after a request with no body framing and after a response
that declared `Content-Length: 0`; it is consequently a wire change from
pre-release 1.0 builds as well as from 0.3.x.

The catalog of abstract shapes that earlier builds defaulted to (46 entries,
`manual-http`, `words`, `base64`, …) is still shipped as release `20260110` and
is reachable with `--defs 20260110`. Thirty-two of its entries have longer
covertexts so that every shipped format can carry a handshake, and the loader
now refuses a release containing a format that cannot (capacity below 128
bytes); its `manual-http-*` formats are unchanged at length 256, carrying 150
(request) and 192 (response) bytes.

## Performance

The encrypted hybrid body and its chunking into fteproxy records are unchanged.
HTTP's carrier framing is not: each body now pays the small chunk-size and
terminal-chunk overhead above. Putting the formatted header in the shortest
covertext that holds one instead of in the format's longest cuts the per-record
header cost by about 7–8x for `http` in the microbenchmark, which is most of the
cost of a hybrid record at ordinary write sizes. Connection setup costs about
1.6 ms more than the same build without the handshake (0.7 → 2.3 ms p50 on
loopback) — two X25519 key generations, four exchanges, and the two extra round
trips that buy server authentication and an in-band destination. See
[PERFORMANCE.md](../PERFORMANCE.md).

## Security

[SECURITY.md](../SECURITY.md) is rewritten around the keypair model: what the
connection string authorises, the replay window and filter, what a failed
handshake looks like from outside, and the allow-rule default. The handshake
is hand-assembled from `cryptography` primitives rather than a Noise library,
and its wire format and key schedule are pinned by checked-in test vectors in
`fteproxy/tests/vectors/handshake_v1.json`.

HTTP chunk framing makes each record parse as one complete message, not a real
HTTP transaction layer. fteproxy requires a byte-preserving direct TCP path;
an HTTP intermediary that rewrites headers or dechunks/rechunks a body breaks
authentication. Requests and responses are generated independently from the
two directions of tunneled traffic, so their counts, timing and fields need not
correspond. Stateful HTTP classification remains outside the threat model.

## Requirements

`fte>=0.4.0,<0.5.0`, `regex2dfa>=0.2.0,<0.3.0`, `cryptography>=42.0`,
Python 3.10 or newer.
