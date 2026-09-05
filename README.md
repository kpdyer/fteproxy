# fteproxy

[![Tests](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml/badge.svg)](https://github.com/kpdyer/fteproxy/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/fteproxy.svg)](https://pypi.org/project/fteproxy/)

* Homepage: https://github.com/kpdyer/fteproxy
* Source code: https://github.com/kpdyer/fteproxy
* Publication: https://kpdyer.com/publications/ccs2013-fte.pdf

## Overview

fteproxy provides transport-layer protection to resist keyword filtering, censorship and discriminatory routing policies.
Its job is to relay datastreams, such as web browsing traffic, by encoding the stream into messages that satisfy a user-specified regular expression.

fteproxy is powered by Format-Transforming Encryption [1] and was presented at CCS 2013.

> **fteproxy 1.0 is not wire-compatible with 0.3.x, and its command line has
> changed.** Upgrade both endpoints together and see
> [Upgrading to 1.0.0](#upgrading-to-100).

[1] [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf), Kevin P. Dyer, Scott E. Coull, Thomas Ristenpart and Thomas Shrimpton

## Requirements

- Python 3.10 or higher
- [libfte](https://github.com/kpdyer/libfte) 0.4.x (`fte>=0.4.0,<0.5.0`),
  `regex2dfa>=0.2.0,<0.3.0`, and `cryptography>=42.0`, all installed
  automatically by `pip`. `cryptography` is a compiled package; wheels exist
  on PyPI for every supported platform.

## Installation

### From PyPI

```bash
pip install fteproxy
```

### From Source

```bash
git clone https://github.com/kpdyer/fteproxy.git
cd fteproxy
pip install -e ".[test]"
```

The `[test]` extra adds `pytest` and `pytest-timeout`; drop it (`pip install -e .`)
if you only want to run fteproxy. Every dependency, including that extra, is
declared in `pyproject.toml` -- there is no `requirements.txt`.

## Usage

Use `fteproxy server` to accept connections and `fteproxy client` to connect.
Run `fteproxy help` for the command list, `fteproxy help client` for a
command's options, or `fteproxy version` for the version and licence.

### Start the server

Once per host. The first start generates the server's keypair and a client
connection file:

```console
$ fteproxy server --advertise vpn.example.com:8080
listening on [::]:8080
key: ~/.local/state/fteproxy/server.key (created)
allowing: globally routable unicast destinations
connection string written to ~/.local/state/fteproxy/connection.txt
```

`connection.txt` is created with mode 0600. It is a capability, so a normal
server start does not print it or put it in logs. Use `--advertise` for the
address remote clients will dial. Without it, an existing endpoint for the same
server identity is preserved; a new connection file contains a valid local
address for same-host use, never an editable `<server-ip>` placeholder. A
wildcard listener uses loopback in a new file. If you deliberately need the URI
on stdout, add `--print-connection`.

### Start the client

Copy `connection.txt` to the client through a secure channel, then point the
client at the file:

```console
$ fteproxy client --connection-file ./connection.txt
checking vpn.example.com:8080 ... ok (protocol 1, http, hybrid)
SOCKS5 on 127.0.0.1:1080

$ curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

Names requested through SOCKS or a forward go through the tunnel and are
resolved by the server, so destination DNS does not leak around the proxy.

The client validates and binds its local listeners before contacting the
server, then checks the server so a wrong connection string fails with a
reason rather than as a timeout on the first real connection:

```console
$ fteproxy client --connection-file ./bad-connection.txt
checking 203.0.113.5:8080 ... failed: no valid handshake reply within 5s
  (wrong connection string, or the server is not running fteproxy 1.0)
$ echo $?
1
```

Pass `--no-check` to skip it.

`--connection-stdin` is convenient for a secret store or a protected pipe:

```bash
fteproxy client --connection-stdin < ./connection.txt
```

The positional URI and `$FTEPROXY_URI` remain compatible, but a URI on the
command line can be exposed by process listings, shell history and diagnostic
tools. Prefer `--connection-file`, `--connection-stdin`, or the implicit state
file. Explicit connection sources are mutually exclusive.

On one host you can leave the argument out entirely — the client reads
`connection.txt` from the state directory:

```bash
fteproxy server &
fteproxy client
```

### A port forward instead of SOCKS

`-L`/`--forward` takes ssh's spelling, and is how you reproduce the
fixed-destination topology fteproxy had before 1.0:

```bash
fteproxy client --connection-file ./connection.txt \
  --forward 2222:127.0.0.1:22
ssh -p 2222 user@localhost
```

`-L`/`--forward` and `-D`/`--socks-listen` are repeatable and can be mixed;
without either, the client opens SOCKS5 on `127.0.0.1:1080`.

Local listeners must use a literal loopback address by default. A wildcard or
other non-loopback bind is rejected unless `--expose-listeners` is present:

```bash
fteproxy client --connection-file ./connection.txt \
  --socks-listen 0.0.0.0:1080 --expose-listeners
```

There is no SOCKS authentication: anyone who can reach an exposed listener can
use the tunnel. Protect it with a host firewall and use the narrowest bind
address possible.

### What the server will dial

With no rules, a server dials only globally routable unicast addresses. It
rejects private, shared, loopback, link-local, unspecified, reserved,
documentation and multicast ranges. The policy is checked both on what the
client asked for and on every address a name resolved to, which also blocks
DNS rebinding into internal services.

`--allow` replaces that policy with a list:

```bash
fteproxy server --allow 127.0.0.1:8081          # only this local service
fteproxy server --allow '*.example.com:443'     # only this domain, only TLS
fteproxy server --allow 10.0.0.0/8              # only this private network
fteproxy server --allow any                     # any name/public destination
```

Rules are repeatable and together form a whitelist. A hostname rule (including
`any`) authorises the requested name, but its resolved address must still be
globally routable. Only an explicit IP address or CIDR rule opts a non-global
address in. A rule naming an address is matched against addresses and CIDRs;
a rule naming a name is matched against names. IPv6 literals go in brackets
when a port follows.

### Formats and record-layer modes

A *format* is a base name from the definitions file, such as `http`; the
request and response covertexts are derived from it. The shipped release,
`20260903`, is five cleartext application protocols -- the case FTE is for,
since a protocol that is normally encrypted is better tunnelled inside the
real thing:

| Format | Ports | Direction split | Mode | Covertext length | What a covertext looks like |
|---|---|---|---|---|---|
| `http` | 80, 8080, 8000 | request / response | hybrid | 200–700 | zero-body HTTP for handshakes/format mode; POST + chunked body in hybrid mode **(default)** |
| `ftp` | 21 | command / reply | format | 64–256 | `USER …`, `220 … ready` control lines |
| `smtp` | 25, 587 | command / reply | format | 80–320 | `EHLO …`, `250-…` command and reply lines |
| `sip` | 5060 | request / response | format | 300–800 | `INVITE sip:…@… SIP/2.0` with Via/From/To/Call-ID/CSeq |
| `dns` | 53 | query / response | format | 90–272 | DNS over TCP: length prefix, header, question, A record |

Every format varies its covertext length: in `format` mode each record picks a
length from across its range, so a captured stream shows a spread of message
sizes instead of one repeated size. The four text formats are framed by a
terminator the format's language cannot produce anywhere else; `dns` is framed
by the two-byte length prefix RFC 1035 puts in front of every DNS-over-TCP
message, which is framing rather than part of its regex, so one pattern serves
every length (and its query names run 72–254 octets rather than always 254).
The two handshake records are always at the top of the range. A `hybrid` mode
header is fixed length too, but at the *shortest* length the format can hold one
in (the `hdr` column below): its sealed payload carries only the length of the
authenticated body behind it, excluding any carrier framing, and a short
covertext is several times cheaper to produce than a long one.

`http` is the default. A client given no `--format` and no `?format=` hint
picks the format whose protocol runs on the server's port -- a server on 21
gets `ftp`, one on 5060 gets `sip` -- and falls back to `http` for a port no
protocol claims. `--format` and the connection string's `?format=` hint both
win over that, and a `--format` that disagrees with the port is honoured with
a warning.

`fteproxy formats` lists the release with each format's role, ports, mode and
the capacity of one covertext:

```console
$ fteproxy formats
name  role      port          mode      hdr  req len  req cap  resp len  resp cap
dns   req/resp  53            format     90   90-272   22-154    90-272    17-148
ftp   req/resp  21            format  91/64   64-256   15-161    64-256    16-163
http  req/resp  80,8080,8000  hybrid    200  200-700   63-448   200-700    52-434  (default)
sip   req/resp  5060          format    300  300-800   99-472   300-800   101-474
smtp  req/resp  25,587        format     80   80-320   20-181    80-320    29-215
```

A range in the length column is a format that varies its covertext length; a
single number is a fixed-length one (the `20260110` shape catalog is all
fixed-length). `hdr` is the covertext length a `hybrid` header goes in --
request and response after a slash when the two differ, as they do for `ftp`,
whose reply pattern has just enough room at 64 bytes and whose command pattern
has not.

The comprehensive catalog of abstract *shapes* that earlier versions defaulted
to -- 46 entries, 23 base names (`manual-http`, `words`, `base64`, …) -- still
ships as release `20260110`: list it with `fteproxy formats --defs 20260110`,
and serve it with `--defs 20260110` on the server.

The client picks the format and the record-layer mode and puts both in the
handshake; the server follows. Nothing has to be configured to match.

- `--mode hybrid` (default): each record is a fixed-length covertext header
  plus authenticated ciphertext. The header goes in the shortest covertext the
  format has room for one in (the `hdr` column above), since its sealed payload
  carries only the body length. The body is raw for the legacy carriers; a
  definition may instead add protocol framing, as `http` does. Fast — hundreds
  of MB/s — but the ciphertext itself remains high entropy.
- `--mode format`: every covertext byte on the wire matches the format regex,
  and each covertext takes a length from across the format's range. Much slower
  (about 1 MB/s), for deployments facing simple entropy or statistical
  detectors. Regex membership does not make the resulting conversation
  indistinguishable from a real implementation; see [SECURITY.md](SECURITY.md).

Each format records the mode it is designed for (the `mode` column above), and
that is what the client uses unless `--mode` says otherwise. `http` is hybrid,
but uses two header grammars. Handshake records and `format`-mode records use
the base regex and are complete zero-body messages; responses explicitly send
`Content-Length: 0`. Post-handshake hybrid data uses a separate regex: requests
are `POST` and both directions advertise `Transfer-Encoding: chunked` (hybrid
responses omit body-forbidden `304`). Each record then carries exactly one
chunk of authenticated ciphertext followed by the terminal zero chunk. For a
non-empty body of `B` bytes, the carrier adds `len(format(B, "x")) + 9` visible
framing bytes around it. The line protocols and `dns` have no natural place for a
high-entropy body, so they ship as `format` -- every covertext byte in the
protocol, at about 1 MB/s, which is fine for interactive use.

This makes each HTTP record syntactically complete, but it is still a direct,
byte-preserving TCP carrier, not an HTTP proxy protocol. An intermediary that
rewrites headers or dechunks/rechunks a message changes authenticated wire
bytes and the tunnel fails closed. Requests and responses are also generated
independently from the two directions of the relayed byte stream: their counts,
timing and fields need not form real HTTP transactions. A stateful HTTP
classifier can use that even though a parser accepts each individual message.

### Command line

Commands are plain words: `server`, `client`, `keygen`, `formats`,
`defs-check`, `version`, and `help`. Options follow the command they configure.

```
fteproxy server  [--listen [HOST]:PORT] [--allow RULE]... [--advertise HOST[:PORT]]
                 [--print-connection] [--state-dir DIR] [--defs RELEASE]
                 [--max-pending N] [--max-pending-per-source N]
                 [--max-active N] [--max-active-per-source N] [-q | -v]
fteproxy client  [URI | --connection-file FILE | --connection-stdin]
                 [-D|--socks-listen [BIND:]PORT]
                 [-L|--forward [BIND:]PORT:HOST:PORT]... [--expose-listeners]
                 [--format NAME] [--mode hybrid|format] [--no-check]
                 [--max-pending N] [--max-pending-per-source N]
                 [--state-dir DIR] [-q | -v]
fteproxy keygen  [--state-dir DIR] [--advertise HOST[:PORT]] [--defs RELEASE]
fteproxy formats [--defs RELEASE]
fteproxy defs-check [--defs RELEASE]
fteproxy version
fteproxy help [COMMAND]
```

| Option | Command | Description | Default |
|--------|---------|-------------|---------|
| `--listen` | server | Address to listen on; `:PORT` means every interface, IPv6 in brackets | `:8080` |
| `--allow` | server | Destination whitelist rule; repeatable. Only explicit IP/CIDR rules may opt non-global addresses in | globally routable unicast only |
| `--advertise` | server, keygen | Address remote clients should dial | preserve this identity's endpoint; otherwise use a valid local address |
| `--print-connection` | server | Deliberately print the capability URI to stdout | URI is written only to `connection.txt` |
| `--defs` | server, keygen, formats, defs-check | Definitions release; server/keygen require YYYYMMDD | 20260903 |
| `URI` | client | Compatibility positional form of `fte://SERVER-ID@HOST:PORT` | not preferred because argv can be observed |
| `--connection-file` | client | Read the URI from a file | with no explicit source: `$FTEPROXY_URI`, then state `connection.txt` |
| `--connection-stdin` | client | Read the URI from standard input | |
| `-D`, `--socks-listen` | client | SOCKS5 listener, `[BIND:]PORT`; repeatable | `127.0.0.1:1080` when no `-D`/`-L` |
| `-L`, `--forward` | client | Forward `[BIND:]PORT` to one `HOST:PORT` through the tunnel; repeatable | |
| `--expose-listeners` | client | Permit non-loopback `-D` and `-L` binds; listeners have no client authentication | rejected without this flag |
| `--format` | client | Base format name (see `fteproxy formats`) | the URI's hint, else the format for the server's port, else `http` |
| `--mode` | client | `hybrid` or `format` | the URI's hint, else `hybrid` |
| `--no-check` | client | Skip the startup check | check runs |
| `--max-pending` | server, client | Bound concurrent handshake/OPEN setup work | server 64; client 32 |
| `--max-pending-per-source` | server, client | Bound concurrent setup work per source IP | server 8; client 16 |
| `--max-active` | server | Bound established relay sessions | 128 |
| `--max-active-per-source` | server | Bound established relay sessions per source IP | 64 |
| `--state-dir` | server, client, keygen | Where `server.key` and `connection.txt` live | `$FTEPROXY_STATE_DIR`, `$XDG_STATE_HOME/fteproxy`, `~/.local/state/fteproxy` |
| `-q` / `-v` | server, client, keygen, formats, defs-check | Errors only / per-connection detail | INFO |

Exit status is 0 after completing a command or on a clean shutdown, 1 on a
runtime failure, 2 on a usage error. The process runs in the foreground and
stops on SIGINT or SIGTERM; there is no daemon mode and no PID file.

Long options are not abbreviated. The CLI validates addresses, rules and
definition identifiers before it creates keys, changes state or contacts a
peer. A newly created state directory is mode 0700; an existing directory with
group or other permissions is refused, not silently changed. Fix an intended
directory yourself with `chmod 700 DIR`. The key and connection file are mode
0600 and are replaced atomically without following a symlink at the target.
Managed reads also reject symlinks, hard links, non-regular files, and files
owned by another user. An explicitly selected connection file remains usable
but warns when its ownership or permissions do not keep the capability private.

### Keys and the connection string

The server holds an X25519 private key in `server.key` (mode 0600, in a
directory with mode 0700). The connection string carries only its public half,
so a client never holds anything that would let it impersonate the server.

`fteproxy keygen` does what the first `fteproxy server` start does, without
starting anything — for provisioning a container or a configuration-management
run:

```bash
fteproxy keygen --advertise vpn.example.com:8080
```

Unlike a normal server start, `keygen` prints the connection URI because
producing it is the command's explicit purpose; it also stores it in
`connection.txt`. Without `--advertise`, it preserves a matching existing
endpoint or uses `127.0.0.1:8080` for a new identity.

For a narrow compatibility case, an old `<server-ip>` invitation is translated
to loopback only when the client finds it implicitly in this host's state
`connection.txt`. The placeholder is rejected from a positional argument, the
environment, stdin, or an explicitly named file; replace it with the server's
real reachable address.

Treat the connection string like a Tor bridge line: whoever holds it can
connect, and its secrecy is what stops an active prober from confirming that
your server is running fteproxy. A prober without it gets no reply at all. It
does not let its holder impersonate the server or read another client's
traffic. See [SECURITY.md](SECURITY.md).

### Python API

```python
import fteproxy

private, public = fteproxy.generate_server_key()

# server side
sock = fteproxy.wrap_socket(conn, server_key=private)
destination = sock.wait_open()      # (host, port), or None if the peer sent data
sock.open_result(0x00)

# client side
sock = fteproxy.wrap_socket(raw, server_id=public,
                            format="http", mode="hybrid")
sock.connect(("203.0.113.5", 8080))
sock.open(("example.com", 443))     # raises fteproxy.OpenRefused(status)
```

`fteproxy.ConnectionString.parse(text)` and `.format()` round-trip the URI. The
[`examples/`](examples/README.md) directory has programmatic, chat,
file-transfer and integration examples.

## Upgrading to 1.0.0

1.0.0 changes the wire format, the command line and the topology. There is no
compatibility mode: a 0.3.x peer, or a peer running an earlier development
build, gets no reply at all. The full notes are in
[docs/release-notes-1.0.0.md](docs/release-notes-1.0.0.md).

- **The command line is new.** Every old flag (`--mode`, `--server_ip`,
  `--client_port`, `--proxy_ip`, `--proxy_port`, `--key`, `--key-file`,
  `--upstream-format`, `--downstream-format`, `--record-layer-mode`,
  `--release`, `--stop`, `--quiet`) is recognised only to print a pointer here
  and exit 2. None of them is aliased, because the meaning changed rather than
  the spelling.
- **The topology changed: the destination is chosen on the client.** The
  server no longer has a forward address, so `--proxy_ip`/`--proxy_port` have
  no equivalent on the server. The old setup

  ```bash
  # 0.3
  fteproxy --mode server --server_port 8080 --proxy_ip 127.0.0.1 --proxy_port 22
  fteproxy --mode client --client_port 8079 --server_ip S --server_port 8080
  ```

  becomes

  ```bash
  # 1.0
  fteproxy server --listen :8080 --allow 127.0.0.1:22
  fteproxy client --connection-file connection.txt \
    --forward 8079:127.0.0.1:22
  ```

  and the same server now also serves `-D` SOCKS5 clients, without being
  reconfigured.
- **The shared key is gone.** So are `--key` and `--key-file`. The server has a
  keypair instead, generated on first start; securely transfer the mode-0600
  `connection.txt` file to clients. Nothing needs a pre-shared secret, and
  there is no public default key to forget to replace.
- **Formats and modes are negotiated, not configured.** One `--format` base
  name on the client replaces `--upstream-format`/`--downstream-format`, and
  `--mode` replaces `--record-layer-mode` on one side only. A mismatch is no
  longer possible.
- **Failures are visible.** The client checks the server at startup and prints
  a reason; a wrong connection string fails in a round trip instead of hanging.
  Exit statuses are meaningful (0/1/2), and a no-argument run prints usage
  instead of crashing.
- **Definitions.** The default release is `20260903`: five real cleartext
  protocols (`http`, `ftp`, `smtp`, `sip`, `dns`), with `http` the default
  format instead of `manual-http`. The 46 abstract shape entries are still
  shipped as release `20260110`, reachable with `--defs 20260110`; thirty-two of their
  entries were given longer covertexts so that every shipped format can carry
  a handshake, and the loader now refuses a release with a format that cannot.
- **API.** `wrap_socket`'s `outgoing_regex`/`incoming_regex`/`K1`/`K2`/
  `negotiate` parameters are replaced by `server_key=` or `server_id=` plus
  `format=`/`mode=`. See [Python API](#python-api).
- **Requires** `fte>=0.4.0,<0.5.0`, `regex2dfa>=0.2.0,<0.3.0`, and
  `cryptography>=42.0`.

See [SECURITY.md](SECURITY.md) for the security model, including what the
handshake and the record layer do and do not authenticate.

## Testing

```bash
python -m pytest fteproxy/tests/ -v
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

Kevin P. Dyer (kpdyer@gmail.com)
