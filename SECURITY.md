# Security Policy

## Supported Versions

Security fixes are applied to the latest release line only. Please upgrade to a
supported version before reporting an issue.

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Security model

fteproxy 0.4 is built on libfte 0.4; read
[libfte's security model](https://github.com/kpdyer/libfte/blob/master/SECURITY.md)
first. The bullets below describe the default definitions negotiation.
The experimental permutation method has the differences described afterward.

- **Threat model.** Format-Transforming Encryption is designed to get past an
  on-path observer that classifies traffic with protocol signatures (regular
  expressions, DPI rules). The shared key protects the confidentiality and
  integrity of the tunnelled bytes against that observer. fteproxy is not a
  general-purpose VPN: it does not hide traffic volume or timing, and the
  limitations below apply.

- **The key.** One 32-byte key, shared by both endpoints, every connection, and
  both directions (`--key` or `--key-file`). Without one, fteproxy uses the
  public constant in `fteproxy/conf.py` and prints a warning at startup; that
  configuration gives no confidentiality or integrity against anyone who has
  read the source. Rotate the key before the number of records sent under it
  approaches 2^32 (every covertext and every hybrid body carries a fresh random
  12-byte nonce; at 2^32 records the chance of a repeat is about 2^-33, and a
  repeat exposes only the two colliding records' contents, never integrity).

- **Authentication and ordering.** Every formatted covertext is a libfte frame:
  AES-128-CTR then HMAC-SHA256 (Encrypt-then-MAC, 128-bit tag). In `hybrid`
  mode the raw record body uses the same construction under subkeys derived
  from the shared key. Every record carries its position in its stream (sealed
  inside the covertext and, in `hybrid` mode, bound into the body tag), so a
  record that is reordered, replayed, or dropped within a connection fails
  authentication and the stream stops.

- **Known limitation: cross-stream replay.** Because the key is static and shared
  by all connections and both directions, a record captured from one stream is
  still valid at the same position of another stream under the same key. An
  active on-path attacker can replay a whole captured stream into a fresh
  connection, or splice record *i* of stream A into stream B. Tunnelled
  protocols with their own authentication (SSH, TLS) detect this themselves;
  plaintext protocols do not. Closing this would need per-connection key
  material in the negotiation (a protocol change); the shared key is a known
  limitation of the 0.4 line, so tunnel protocols that authenticate themselves
  where this matters.

- **What an observer sees.** In `hybrid` mode (the default) only the first
  `length` bytes of each record are in the target format; the rest of the
  record is high-entropy ciphertext, and its length (the plaintext length plus
  28 bytes) is visible. In `format` mode every byte on the wire is in the
  target format. Sealed covertexts are always exactly `length` bytes and use
  the format's whole rank space, so a short message neither shortens the
  covertext nor leaves a run of the format's lowest character.

- **No protocol-version handshake.** The 0.4 wire format is not compatible with
  0.3.x, and the record-layer mode must match on both endpoints. A mismatch is
  a failed negotiation: the server logs a warning when the peer closes, and
  the client sees a timeout. Nothing is sent in the clear in either case.

- **Patterns and lengths are trusted input.** The server compiles only the
  formats in its own definitions file; a client's negotiation cell can name one
  of them but cannot supply a pattern. Never load a definitions file (`--release`)
  from an untrusted source: as libfte documents, a hostile pattern can make DFA
  construction take exponential time and memory.

- **Negotiation cost.** For every new connection the server tries to decrypt
  the first bytes as each known request format until one succeeds (the
  configured `--upstream-format` first). A failed attempt is rejected before
  the tag check when the bytes are not in the format, as in libfte; a full scan
  over the built-in formats costs a few milliseconds of CPU.

### Experimental permutation negotiation

The Python API can opt into `negotiation="permutation"`; both peers must select
it explicitly. See the [protocol guide](docs/permutation-bootstrap.md).

- **Client-provided patterns.** The server authenticates the complete offer
  before compiling either regex. Every holder of the PSK is therefore trusted
  to provide patterns. The 220-byte combined regex limit and 512-byte covertext
  limit do not bound DFA construction cost; this mode provides no compilation
  sandbox. Do not share its key with untrusted clients.
- **Bootstrap protection.** A 256-byte ChaCha20-Poly1305 envelope is carried by
  an exact-domain FF1 permutation of 320 complete covertexts. Independent
  HMAC-derived keys separate these operations from handshake and data keys.
  The context binds the multiset, selected word length, batch count, and wire
  version. The bootstrap uses fresh random 96-bit nonces under the PSK-derived
  AEAD key; nonce uniqueness remains a cryptographic requirement.
- **Session binding.** The server returns a fresh 128-bit challenge in an
  authenticated FTE record bound to the bootstrap digest. The client confirms
  possession of the resulting upstream session key before the server releases
  application data. Data keys bind the challenge, transcript, and direction,
  preventing captured records from authenticating in a fresh session except
  with negligible cryptographic probability. Replaying an initial batch can
  still cause authentication work, compilation, and a fresh response; there is
  no bootstrap replay cache or active-probing resistance claim. PSK compromise
  exposes recorded sessions; the handshake provides no forward secrecy.
- **Bounds and failures.** The receiver tries at most 512 candidate lengths
  while buffering at most 160 KiB of bootstrap data. The blocking handshake
  has a five-second network deadline, or the caller's shorter socket timeout;
  it cannot preempt native regex compilation. Failed handshakes close the
  connection. Application records retain position authentication and fail
  closed on invalid or truncated records.
- **Cover distribution.** The permutation argument applies to exchangeable
  batches; the socket API samples independent uniform words from a regex's
  fixed-length slice. It does not preserve arbitrary stateful conversations,
  hide volume or timing, or prove full active steganographic security. Every
  bootstrap word matches the upstream regex, while the complete batch is a
  concatenation of 320 such words. Later `hybrid` bodies remain unformatted.

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
