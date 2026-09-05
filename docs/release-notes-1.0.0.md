# fteproxy 1.0.0

1.0 changes the wire protocol, command line, and proxy topology.
It does not interoperate with 0.3.x. Earlier 1.0 development changes also
altered framing, so endpoints need matching builds and definitions.
Upgrade both endpoints together. These notes describe the 1.0 behavior in this
checkout.

## Changes

- **Server identity:** an X25519 keypair replaces shared symmetric-key
  configuration. The first server start creates `server.key` and a private
  `connection.txt`. Clients receive the public-key connection capability.
- **Handshake:** protocol v1 authenticates the server and derives session keys
  for each direction using ephemeral X25519 exchanges, HKDF, and HMAC.
  Invalid hellos receive no protocol reply; replay tracking and concurrency
  limits bound some forms of abuse.
- **Client-selected destinations:** SOCKS5 CONNECT and `-L` forwards send
  an OPEN request through the tunnel. The server applies its allow rules,
  connects, and returns an OPEN_RESULT.
- **Destination policy:** only globally routable unicast addresses are allowed
  by default. Explicit rules replace that policy; only IP/CIDR rules permit
  non-global results. `--allow any` alone does not expose private services.
- **Local listeners:** `-D` and `-L` are repeatable and may be mixed.
  Without either, SOCKS5 listens on `127.0.0.1:1080`. Non-loopback binds
  require `--expose-listeners`; listeners have no client authentication.
- **CLI:** named commands replace the old top-level flags. Startup validates
  and binds listeners before checking the server. Exit statuses are
  0 for success/clean shutdown, 1 for runtime failure, and 2 for usage errors.
- **Capability handling:** file/stdin input keeps URIs out of argv. A normal
  server start stores its URI without printing it; `--print-connection`
  opts in. `keygen` stores and prints it without starting a server.
  New invitations use usable addresses; an existing endpoint for the same
  identity is preserved unless `--advertise` overrides it.
- **State and logging:** private state directories, atomic file writes,
  checked managed reads, and pattern-based log redaction.
- **Stream lifecycle:** CLOSE supports half-close so the other direction can
  finish delivering data.

See [SECURITY.md](../SECURITY.md) for the guarantees and limitations,
including replay-filter eviction, rejection timing, and exposed listeners.

## Upgrade

On the server, replace the address below with one clients can reach.
This example permits only the local SSH service:

```bash
fteproxy server --advertise vpn.example.com:8080 --allow 127.0.0.1:22
```

Securely copy the resulting `connection.txt` to the client. Replace the old
fixed-destination client with:

```bash
fteproxy client --connection-file ./connection.txt -L 8079:127.0.0.1:22
```

The `-L` destination replaces the old server's
`--proxy_ip`/`--proxy_port`. Omit `-L` for a SOCKS5 listener, and give
the server allow rules appropriate to the destinations applications need.

Old top-level `--mode client|server`, address flags, `--key`,
`--key-file`, directional format flags, `--record-layer-mode`,
`--release`, `--stop`, and `--quiet` are removed.
The new `client --mode hybrid|format` selects the record mode.
`--version` still aliases `version`. There is no daemon mode or PID file;
use a service manager or send SIGINT/SIGTERM.

Shared-key files are no longer used. For embedded applications, replace
`outgoing_regex`, `incoming_regex`, `K1`, `K2`, and `negotiate`
with `server_key=` or `server_id=`, plus client `format=`/`mode=`
and matching `defs=`. See the
[Python examples](../examples/programmatic/README.md).

## Definitions and HTTP framing

The default release is `20260903`: HTTP, FTP, SMTP, SIP, and DNS over TCP,
each with request/response formats. The CLI picks a format from the server port,
falling back to HTTP. Flags and URI hints override that choice.
The default mode follows the selected format's hint: hybrid for HTTP, format
for the other four.

All five vary their format-mode record lengths over eight values. The four
text formats use terminators; DNS uses a two-byte prefix outside its regex.
Handshakes use maximum-length covertexts. Hybrid headers use the shortest
allowed length that holds a header, shown by `fteproxy formats` as `hdr`.

HTTP handshake and format-mode records are zero-body messages. Hybrid data
uses POST requests and body-permitted responses with
`Transfer-Encoding: chunked`, one ciphertext chunk, and a terminal zero chunk.
This replaces earlier development builds that appended ciphertext without
valid HTTP body framing.

HTTP records can be parsed individually, but requests and responses are
independent. They need not form valid transactions. The carrier requires a
direct TCP path that preserves bytes; HTTP intermediaries that rewrite headers
or rechunk bodies are unsupported.

Release `20260110` retains 46 fixed-length shape entries (23 pairs).
Use `--defs 20260110` on the server and distribute its connection file.
Both peers still need matching definitions; negotiation does not transfer them.

## Requirements and validation

Requires Python 3.10+, `fte>=0.4.0,<0.5.0`,
`regex2dfa>=0.2.0,<0.3.0`, and `cryptography>=42.0`.

```bash
python3 -m pip install -e ".[test]"
python3 -m pytest --timeout=300
python3 -m fteproxy defs-check
```

[PERFORMANCE.md](../PERFORMANCE.md) contains historical measurements with
their revision and environment. The archived HTTP timings predate chunk
framing and should not be quoted as current-carrier benchmarks.
