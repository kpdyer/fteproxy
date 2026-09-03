# fteproxy 1.0.0

1.0.0 replaces the protocol, the command line and the topology together,
because none of the three worked without the other two. The short version: a
server needs no arguments, a client needs one, and there is no shared secret.

```console
$ fteproxy server
listening on [::]:8080
key: ~/.local/state/fteproxy/server.key (created)
clients connect with:
  fteproxy client fte://Qm3s…ZzE@<server-ip>:8080?defs=20260903

$ fteproxy client fte://Qm3s…ZzE@203.0.113.5:8080
checking 203.0.113.5:8080 ... ok (protocol 1, http, hybrid)
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
  (mode 0600, in a directory with mode 0700) and prints
  `fte://<server-id>@<host>:<port>`, also writing it to `connection.txt`
  alongside. `--advertise` fills in the address; `fteproxy keygen` does the
  same without starting a server, for provisioning. A client holds only the
  public half.
- **Protocol version 1: a real handshake.** The Noise `NK` pattern
  (`e, es` then `e, ee`) over X25519, HKDF-SHA256 and HMAC-SHA256, giving
  server authentication, forward secrecy, and a separate header key and body
  key for each direction of each connection. That closes the cross-stream
  replay limitation the shared-key line documented. Both handshake records are
  ordinary covertexts, so the shape on the wire is unchanged.
- **A failed handshake is answered with silence.** Wrong key, wrong format,
  stale clock, replayed hello: all identical from outside — no reply, read and
  discard for a random 1 to 5 seconds, then close. A replay filter keyed on the
  client's ephemeral key covers the ±1 hour epoch window.
- **SOCKS5 and ssh-style forwards.** `-D [BIND:]PORT` is a SOCKS5 CONNECT
  listener (the default is `127.0.0.1:1080`); `-L [BIND:]PORT:HOST:PORT` is a
  fixed forward. Both are repeatable and can be mixed. Names are resolved at
  the far end, so client DNS does not leak around the tunnel.
- **`--allow` rules on the server.** By default every destination except the
  server's own loopback and link-local addresses, checked on the request *and*
  on what the name resolved to. `--allow 127.0.0.1:8081` publishes one local
  service; `--allow any` restores everything.
- **A startup check.** The client opens one short session before binding
  anything and prints `checking HOST:PORT ... ok (protocol 1, format, mode)`,
  or a reason and exit 1. `--no-check` skips it.
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
  server-id or a connection string out of any log line. Command output — the
  connection string, the format table — goes to stdout so it can be piped.

## Upgrade steps

1. Upgrade both endpoints to 1.0.0 at the same time. There is no window in
   which a 0.3 client and a 1.0 server interoperate.
2. Start the server once and keep the connection string it prints:

   ```bash
   fteproxy server --advertise your.host:8080 --allow any
   ```

   Choose the `--allow` rules deliberately; the default blocks the server's own
   loopback, which is usually what you want but is not what 0.3 did.
3. Give the connection string to each client, and translate the old
   fixed-destination setup into a `-L` forward:

   ```bash
   # 0.3
   fteproxy --mode client --client_port 8079 --server_ip S --server_port 8080
   # 1.0, with the server's --proxy_ip:--proxy_port as the -L destination
   fteproxy client fte://…@S:8080 -L 8079:127.0.0.1:22
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

The four text formats no longer emit every covertext at one length. In `format`
mode each record picks a covertext length from across the format's range --
`http` 200–700 bytes, `sip` 300–800, `smtp` 80–320, `ftp` 64–256 -- and the
decoder frames the wire on the format's terminator (`\r\n\r\n`, or `\r\n` for
the line protocols) rather than on a fixed slice, so a capture shows a spread of
message sizes instead of one repeated size. The choice leans short for
interactive traffic and long for bulk. Three things stay fixed length: `dns`
(its two-byte length prefix is a literal in the regex, so each length would need
its own regex), a `hybrid` mode header, and the two handshake records, which are
always at the top of the format's range. `http-response` lost its body field to
make this safe -- a field that could contain CRLF CRLF would break terminator
framing -- and is now a header-block-only 200/302/304/404 response with
`Content-Length: 0`.

The catalog of abstract shapes that earlier builds defaulted to (46 entries,
`manual-http`, `words`, `base64`, …) is still shipped as release `20260110` and
is reachable with `--defs 20260110`. Thirty-two of its entries have longer
covertexts so that every shipped format can carry a handshake, and the loader
now refuses a release containing a format that cannot (capacity below 128
bytes); its `manual-http-*` formats are unchanged at length 256, carrying 150
(request) and 192 (response) bytes.

## Performance

Bulk throughput is unchanged: the record layer's framing, sealing and chunking
are as they were, and the hybrid body still runs at 670–970 MB/s in the
microbenchmark. Connection setup costs about 1.6 ms more than the same build
without the handshake (0.7 → 2.3 ms p50 on loopback) — two X25519 key
generations, four exchanges, and the two extra round trips that buy server
authentication and an in-band destination. See
[PERFORMANCE.md](../PERFORMANCE.md).

## Security

[SECURITY.md](../SECURITY.md) is rewritten around the keypair model: what the
connection string authorises, the replay window and filter, what a failed
handshake looks like from outside, and the allow-rule default. The handshake
is hand-assembled from `cryptography` primitives rather than a Noise library,
and its wire format and key schedule are pinned by checked-in test vectors in
`fteproxy/tests/vectors/handshake_v1.json`.

## Requirements

`fte>=0.4.0,<0.5.0`, `cryptography>=42.0`, Python 3.10 or newer.
