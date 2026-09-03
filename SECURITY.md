# Security Policy

## Supported Versions

Security fixes are applied to the latest release line only. Please upgrade to a
supported version before reporting an issue.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security model

fteproxy 1.0 is built on libfte 0.4; read
[libfte's security model](https://github.com/kpdyer/libfte/blob/master/SECURITY.md)
first. This section covers what fteproxy adds on top of it.

- **Threat model.** Format-Transforming Encryption is designed to get past an
  on-path observer that classifies traffic with protocol signatures (regular
  expressions, DPI rules), and against an active prober that opens connections
  to a suspected server to see what answers. fteproxy is not a general-purpose
  VPN: it does not hide traffic volume or timing, and the limitations below
  apply.

- **The server keypair.** A server holds a long-term X25519 keypair in
  `server.key` (mode 0600, in a state directory with mode 0700), generated on
  first start. The public half is the *server-id* in the connection string.
  There is no shared secret and no default key: a client holds nothing that
  would let it impersonate the server, and there is no public constant to
  forget to replace.

- **What the connection string authorises.** The connection string is
  `fte://<server-id>@<host>:<port>`. Both handshake records are sealed under
  `K_cover = HKDF-SHA256(S_pub, "fteproxy/v1/cover")`, which every holder of
  the string can compute. That is the point: holding the string is what
  authorises a connection attempt, and a prober that does not hold it gets no
  reply at all. Treat it like a Tor bridge line — its secrecy is what stops an
  active prober confirming the server. It does **not** let its holder
  impersonate the server (the server hello's MAC needs the private key) nor
  read another client's session (the session keys come from two ephemeral
  keys), and a holder who is not on the path cannot learn another client's
  traffic at all.

- **The handshake.** Protocol version 1 is the Noise `NK` message pattern
  (`e, es` then `e, ee`), hand-assembled from `cryptography`'s X25519, HKDF and
  HMAC rather than taken from a Noise library, because the maintained options
  are thin and the pattern is thirty lines. It gives server authentication and
  forward secrecy; it does not authenticate the client beyond possession of
  the connection string, which is the property obfs4 has. Every handshake byte
  is bound into `H = SHA-256("fteproxy/v1" || S_pub || client hello || s_pub)`,
  which is both the key schedule's salt and the server's MAC input, so a
  tampered hello produces different keys on the two ends rather than a session.
  An all-zero X25519 shared secret is refused explicitly. The wire format and
  the key schedule are pinned by test vectors in
  `fteproxy/tests/vectors/handshake_v1.json`, generated once from fixed seeds;
  `fteproxy/tests/test_handshake.py` checks them and tampers with every field
  of both records, one at a time.

- **Per-connection, per-direction keys.** The handshake derives five keys:
  `K_auth_s` and a header key and a body key for each direction. No two
  connections and no two directions share a record key, which closes the
  cross-stream replay limitation the shared-key line documented, and gives
  forward secrecy: compromising `server.key` later does not decrypt a recorded
  session. Rotate a connection's keys by opening a new connection; the old
  advice to rotate a shared key before 2^32 records no longer applies, since a
  key covers one direction of one connection.

- **Authentication and ordering.** Every formatted covertext is a libfte
  frame: AES-128-CTR then HMAC-SHA256 (Encrypt-then-MAC, 128-bit tag). In
  `hybrid` mode the raw record body uses the same construction under subkeys
  derived from that direction's body key. Every record carries its position in
  its stream (sealed inside the covertext and, in `hybrid` mode, bound into the
  body tag), so a record that is reordered, replayed, or dropped within a
  connection fails authentication and the stream stops. Every record also
  carries a type byte; a type this version does not define closes the
  connection rather than being guessed at.

- **Replay window and filter.** A client hello carries an *epoch*: hours since
  the Unix epoch, accepted within plus or minus one hour. The server remembers
  the client ephemeral public key of every hello it accepted inside that
  window, bucketed by epoch, and refuses a repeat. So a recorded hello can
  only be replayed inside a window of up to three hours -- the hour it names
  plus the one on either side, since both are accepted -- and inside that
  window the filter refuses it, while past it the epoch check does. The
  filter is in memory only and bounded; past its cap it drops entries from
  whichever hour holds the most, so a flood cannot evict the hour real clients
  are using, only itself. A flood that names the *current* hour shares that
  bucket with real clients and can push their entries out, re-enabling replay
  of those hellos inside the window; mounting it needs the connection string,
  so it grants its holder nothing a fresh handshake does not, and a
  pre-authentication rate limit is the real bound. The check runs last, so a hello refused for any other
  reason cannot be used to fill the filter and lock out a real client.

- **Behaviour on a failed handshake.** Every rejection is answered
  identically: no reply, read and discard, then close, and one line in the
  DEBUG log. The close comes a random 1 to 5 seconds after the handshake
  timeout has run out, counted from when the connection was accepted -- not
  from when the check failed, which would separate the rejections that are
  decided on the first record from those that are only decided when the
  timeout expires, and let one replayed capture confirm the server. Unknown
  version, a reserved flag bit, the wrong definitions release, an unknown
  format, a stale epoch, a replayed hello and a hello sealed under someone
  else's key are indistinguishable from each other and from a service with
  nothing to say. This is obfs4's behaviour and is what stops an active prober
  learning anything from a bad guess.

- **Which destinations a server will dial.** By default every destination
  *except* the server host's own loopback and link-local addresses, checked
  both on what the client asked for and on every address the name resolved to,
  so `localhost` or a rebinding name does not walk around it. `--allow`
  replaces that with a list: only what the rules name is reachable, and
  `--allow any` restores everything including loopback. Without this a
  connection string would be a route into every service bound to the server's
  own loopback.

- **What an observer sees.** In `hybrid` mode (the default) only each record's
  fixed-length covertext header is in the target format; the rest of the
  record is high-entropy ciphertext, and its length (the plaintext length plus
  29 bytes) is visible. In `format` mode every byte on the wire is in the
  target format, and each record's covertext takes one of the lengths its
  format may emit (see the next point). A sealed covertext always uses the
  format's whole rank space at whatever length it was sealed at, so a short
  message neither shortens the covertext nor leaves a run of the format's
  lowest character. The two handshake records are one request-format covertext
  and one response-format covertext, both at the format's longest length: a
  connection therefore opens with two records of a size fixed by the format,
  whatever the data records after them do.

- **How realistic a covertext actually is.** The five shipped formats
  (`http`, `ftp`, `smtp`, `sip`, `dns`) model real message *structure*: every
  sealed covertext parses as a valid message of its protocol -- correct verb or
  status line, mandatory headers, terminators -- and, because the record layer
  pads each plaintext to the format's full capacity with random bytes before
  encrypting, every variable field is filled with high-entropy characters from
  its own class rather than a low-entropy run. That is enough to pass a regex
  or keyword DPI rule, which is the threat model FTE is for. It is **not**
  enough to pass a classifier that looks at content or behaviour, for two
  reasons inherent to uniform rank sampling:

  - **Field values are random.** A covertext's URL path, hostname, mail
    address, SIP tag or DNS label is a random string from the field's
    character class, not a plausible value: a 300-character random path, not
    `/index.html`; a random Call-ID, not one a phone would mint.
  - **Message lengths vary, but they are not a real length distribution.**
    Every covertext of a format used to be exactly `length` bytes, so a
    length-distribution test separated a tunnel from real traffic without
    reading a byte. In `format` mode every shipped format now chooses a
    covertext length per record from eight lengths spanning the format's range
    -- weighted towards short lengths for interactive traffic and long ones for
    bulk -- so a capture shows a spread of message sizes rather than one
    repeated size. The four text formats (`http`, `ftp`, `smtp`, `sip`) are
    framed by a terminator; `dns` is framed by the two-byte length prefix that
    RFC 1035 section 4.2.2 puts in front of every DNS-over-TCP message, which
    is framing rather than part of its regex, so one pattern serves all eight
    of its lengths. What a spread does *not* show is the protocol's own length
    distribution: eight discrete values, sized by what the record layer is
    carrying, are not the continuous, content-driven lengths of real HTTP or
    SIP, and an adversary who models message lengths finely can still tell the
    difference. Two things stay fixed: a `hybrid` header, and the two handshake
    records, which are always at the format's longest length.
  - **One message type dominates.** Unranking a full-capacity plaintext lands
    in the same branch of the alternation nearly every time, so in practice
    every `http` request samples as `GET`, every `sip` request as `ACK`, every
    `ftp` request as `CWD`, every `smtp` request as `VRFY`, and every `ftp`
    reply as `150`. Variable length does not fix this: which branch dominates
    depends on the covertext length, so a stream now shows a *few* message
    types instead of exactly one, and each length still shows one of them
    almost exclusively. A stream that is all `ACK` with no `INVITE`, or all
    `CWD` with no login, is not a conversation any real client would have.
  - **Replies do not answer their requests.** Every covertext is an
    independent unranking of an independently randomised ciphertext, so
    nothing in the record layer can make a reply depend on the request it
    follows. For `dns` that is a concrete and cheap tell: a response's
    16-bit ID and its question section never match the query's, a
    stateless two-field check that resolvers, connection-tracking DNS
    helpers and DNS-aware middleboxes already run. Over TCP it is largely
    moot; over UDP port 53 it would be the first thing flagged. Making a
    reply echo its request would be a protocol change, not a format
    change (see `docs/udp-feasibility.md`).

  Nothing in the protocol depends on this: confidentiality and integrity come
  from the handshake and the record layer, not from how convincing a covertext
  is. What a weak covertext costs you is *unobservability* against an
  adversary better than a signature matcher.

- **Mode choice leaks differently per format.** `hybrid` formats only each
  record's fixed-length header and sends the body as raw authenticated
  ciphertext, so the bytes past the header are high-entropy. For `http` that
  reads as a message with a body, which is what HTTP looks like. For a line
  protocol (`ftp`, `smtp`, `sip`) or for the binary `dns` format there is no
  place a high-entropy tail belongs, so those ship as `mode_hint: format`
  (every byte in the protocol, at about 1 MB/s) and running them under
  `--mode hybrid` leaks an obvious high-entropy tail after each line -- and,
  because a `hybrid` header is fixed length, gives back the length fingerprint
  the format-mode records no longer have. `dns` in `hybrid` mode is worse than
  the others: a DNS message is self-delimiting, so a raw body after the
  covertext is a tail the length prefix does not account for -- visible to
  anything that reads DNS-over-TCP framing at all.

- **A `dns` query name is long, though no longer always the same length.** The
  DNS header is 12 fixed bytes and the question trailer is 4 more, so a
  covertext's capacity lives almost entirely in the QNAME. At the fixed
  272-byte covertext `dns` shipped before, *every* query padded out to a
  254-octet name -- legal, under RFC 1035's 255-octet limit, and far longer
  than any name real traffic resolves. Length-prefix framing removed the
  fixed part of that: a query name now runs from 72 octets at the shortest
  covertext to 254 at the longest (56 to 238 for a reply), so a capture shows
  a range of name sizes. The 254-octet pad is now the *maximum* rather than
  every record, but the range still sits above what a real resolver mostly
  sees, and the short end is where it is because a shorter DNS message has too
  small a rank space to carry a record at all.

- **Nothing secret is logged.** The package logger carries a redaction filter,
  installed at import, that strips a connection string's server-id, a hex key
  and a bare base64url public key out of any message before a handler sees it.
  Command output — the connection string a server prints, the format table —
  goes to stdout; logs go to stderr.

- **Patterns and lengths are trusted input.** The server compiles only the
  formats in its own definitions file; a client's hello can name one of them
  but cannot supply a pattern, a length, or a length range. Never load a
  definitions file (`--defs`) from an untrusted source: as libfte documents, a
  hostile pattern can make DFA construction take exponential time and memory,
  and a variable-length entry multiplies that by the number of lengths it
  declares (a fixed eight per format, so the multiplier is bounded).

- **First-record cost.** For every new connection the server tries to unseal
  the first covertext as each known request format until one succeeds, most
  recently matched first, so a server whose clients share a format pays one
  attempt. A full scan over the built-in formats costs well under a
  millisecond of CPU, and the attempt is bounded by a handshake deadline and a
  64 KiB buffer cap, so a peer that connects and falls silent does not occupy a
  worker.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Instead, report them privately through GitHub's **private vulnerability
reporting**:

1. Go to the repository's **[Security tab](https://github.com/kpdyer/fteproxy/security)**.
2. Click **Report a vulnerability** to open a private advisory.
3. Provide as much detail as you can, ideally including:
   - a description of the vulnerability and its impact,
   - the affected version(s),
   - step-by-step reproduction instructions or a proof of concept,
   - any suggested remediation.

You can also open the report directly at:
<https://github.com/kpdyer/fteproxy/security/advisories/new>

### What to expect

- We aim to acknowledge new reports within **7 days**.
- We will keep you informed of progress as we investigate and prepare a fix.
- Once a fix is available, we will coordinate disclosure and credit you in the
  advisory unless you prefer to remain anonymous.

Thank you for helping keep fteproxy and its users safe.
