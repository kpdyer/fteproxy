# Whole-cover permutation bootstrap

An opt-in negotiation for clients whose server has no regex catalog: send a
fixed batch of complete valid covertexts and encode the description only in
their order. The receiver discovers both regexes and upstream length by
bounded authenticated trials.

Permutation negotiation is selected explicitly. There is no autodetection or
fallback from one negotiation method to another: both endpoints must request
`negotiation='permutation'`. The legacy `negotiation='definitions'` mode
remains the default. This construction does not claim full steganographic
security.

## The idea

Let `R_b` be the language accepted by the client's regex at fixed word length
`b`. The client samples `k = 320` independent words

```
W = (w₁, …, wₖ),       wᵢ ∈ R_b,
```

then treats the words as a multiset `S`. If `c_w` is the multiplicity of word
`w` in `S`, the number of distinct orders is

```
N(S) = k! / ∏w c_w! .
```

The client encrypts a fixed-size descriptor envelope and maps it to an integer
in `[0, N(S))`. A keyed FF1 permutation is used over the *whole* rank domain;
the resulting rank is decoded with multiset unranking to select the order of
the original words. No word is changed, discarded, or appended with an
unconstrained ciphertext suffix. Every individual word remains in `R_b`, but
the complete bootstrap belongs to `R_b^320`, not generally to one word of
`R_b`.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    C->>C: Choose regex and b; sample 320 iid words from R_b
    C->>C: Build multiset S and rank space N(S)
    C->>C: AEAD-encrypt descriptor; FF1-permute rank; unrank S
    C->>S: Send the 320 reordered words (320b bytes)
    loop b = 1 … 512, as bytes arrive
        S->>S: Split first 320b bytes; rank observed order
        S->>S: Reverse FF1 and verify AEAD
    end
    S->>S: Generate challenge; derive bootstrap response key
    S-->>C: Sealed downstream FTE record with fresh 16-byte challenge
    S->>S: Derive both directional session keys
    C->>C: Verify challenge record
    C->>C: Derive both directional session keys
    C->>S: Sealed 16-byte key confirmation in upstream R
    S->>S: Verify confirmation; permit application records
    Note over C,S: Application records use the negotiated formats and session keys
```

The public framing rules are deliberately small and fixed:

| Parameter | Value | Consequence |
| --- | ---: | --- |
| Words per batch, `k` | 320 | The receiver tests a bounded set of record endings. |
| Encrypted descriptor envelope | 256 bytes | Includes nonce and authenticated ciphertext. |
| Maximum descriptor payload | 226 bytes | Two-byte length, 12-byte nonce, and 16-byte tag consume the remainder. |
| Maximum candidate word length | 512 bytes | The receiver's scan is bounded at `320 × 512` bytes. |
| Bootstrap wire size | `320b` bytes | At `b = 256`, this is 81,920 bytes (80 KiB). |

The receiver needs no catalog or pre-shared length. It compiles learned regexes
only after authentication. Both formats need at least 28 bytes of FTE
plaintext capacity: a 12-byte seal plus a 16-byte control value.

## Public API

The client supplies both regexes and lengths; the server supplies only the
shared 32-byte PSK:

```python
# Client: outgoing is client → server; incoming is server → client.
wrapped = fteproxy.wrap_socket(
    sock,
    negotiation="permutation",
    key=key,                         # exactly 32 bytes
    outgoing_regex=upstream_regex,
    outgoing_length=256,
    incoming_regex=downstream_regex,
    incoming_length=256,
    record_layer_mode="format",
)

# Server: the offer supplies both regex texts and the downstream length.
wrapped = fteproxy.wrap_socket(sock, negotiation="permutation", key=key)
```

The handshake is lazy on first `send()` or `recv()`; `do_handshake()` makes it
explicit. The client defaults to `record_layer_mode="format"`; the mode is
authenticated in the offer. A server accepts it unless its own mode constrains
it. After negotiation, `wrapped.parameters` exposes both regexes, lengths,
and the mode, with directions always relative to the client. There is no CLI
flag for this experimental method.

## Why reordering preserves an iid source

For an iid source with word probabilities `p(w)`, every order of a fixed
multiset has the same probability:

```
Pr[(w₁, …, wₖ)] = ∏w p(w)^c_w .
```

Uniformly selecting one of the `N(S)` distinct orders therefore leaves the
distribution unchanged; the same holds for any exchangeable batch.

The exact statement concerns a uniform order. The implementation uses FF1
and makes a computational claim under its pseudorandom-permutation assumption,
with separate AEAD and permutation keys. A fresh ideal permutation per context
gives a uniform order; repeated contexts require a multiple-query analysis.
The socket API samples independent uniform words from the regex, while the
standalone codec accepts caller-provided batches. Neither provides a full
steganographic proof for the handshake and its observable responses.

This assumption is the boundary. A stateful source that always emits
`A` followed by `B` does not remain distributed the same after random
reordering: `B,A` appears with probability 1/2 even though it was impossible
before. The implementation uses one fixed batch; stopping at the first prefix
with enough capacity would need a new distribution argument.

This follows permutation coding for unknown iid covertext sources (Ryabko and
Ryabko 2006, [Theorem 2 and Corollary 2](https://arxiv.org/pdf/cs/0606085)).
Applying it to authenticated FTE bootstrap and discovering `b` through
authentication is an engineering experiment, not a novelty claim.

## Capacity, duplicates, and a small example

The envelope is 256 bytes, or 2,048 bits. With 320 distinct words,

```
floor(log₂(320!)) = 2,206 bits,
```

so the rank space is sufficient. Duplicates reduce capacity through the
denominator in `N(S)`; encoding fails when `N(S) < 2^2048`, even though the
regex remains valid.

For example, suppose a toy batch has three distinct word values `A`, `B`, and
`C`, with four words total: `S = {A, A, B, C}`. It has

```
N(S) = 4! / 2! = 12
```

distinct orders. With zero-based lexicographic ranking:

| Rank | Transmitted order |
| ---: | --- |
| 0 | `A A B C` |
| 1 | `A A C B` |
| 7 | `B A C A` |
| 11 | `C B A A` |

The receiver observes the same four words, reconstructs the twelve-order
domain, and recovers the rank. It never needs the regex that produced them.

If the source has min-entropy `h`, a conservative sufficient-condition bound
for a duplicate is

```
Pr[insufficient capacity] ≤ Pr[any duplicate]
                       ≤ choose(320, 2) · 2⁻ʰ.
```

At `h = 128`, this upper bound is approximately `2⁻¹¹²·³⁶`. It is an
assumption about the source and a bound on one failure mode, not a measured
failure rate or a security parameter. A perfectly valid regex with very small
support can still produce an inadequate multiset.

## Offer and authenticated key confirmation

The descriptor carries the protocol version, requested record-layer mode,
downstream length, and both UTF-8 regex texts. The combined UTF-8 regex text
budget is 220 bytes. Six bytes of binary metadata fit with that text in the
226-byte descriptor payload; the selected upstream length is inferred from the
successful bounded authentication trial rather than sent as clear metadata.
The mode is therefore both negotiated and authenticated by the descriptor's
AEAD.

After the batch is decoded, the server derives a response key from the PSK and
bootstrap transcript digest, then sends a sealed FTE record in `R_down` whose
control plaintext is a fresh 16-byte challenge. The client verifies that record
before deriving separate client-to-server and server-to-client session keys
from the PSK, digest, and challenge. It then sends a sealed 16-byte
key-confirmation record in `R_up` using the new client-to-server key. The server
derives those session keys before verifying confirmation and accepts application
data only after it verifies. Session-key cipher instances are per-connection,
not globally cached.

After confirmation, the existing FTE record layer is reused with the negotiated
regexes and `record_layer_mode`.

### Bootstrap authentication

The multiset and the order rank jointly identify the cover bytes. The
multiset, width, batch count, alphabet, and multiplicities are included in
AEAD associated data. Changing a word changes that data; changing only the
order changes the rank and therefore the recovered envelope. The receiver
accepts a candidate only after the inner AEAD check succeeds. The low-level
codec has no counter field.

This gives record integrity for the bootstrap, but it does not implement
counter-based replay protection. An unchanged batch can be replayed at the
bootstrap layer. The fresh challenge and key confirmation bind a live
application session to the bootstrap transcript; the server still accepts
application data only after confirmation.

The design does not hide traffic volume or timing. In `hybrid` mode, later
record bodies remain visible high-entropy ciphertext; AEAD success is not proof
of statistical indistinguishability.

## Design trade-offs

Whole-cover permutation avoids byte-permutation closure requirements and an
unconstrained tail, at the cost of `320b` bytes, bounded trials, and the
iid/exchangeability assumption. A hybrid tail is smaller but exposes its body;
an invariant may not exist. The method does not preserve arbitrary dialogues or
contradict the general channel lower bound; it relies on one exchangeable
batch distribution (Dedić, Itkis, Reyzin, and Russell 2008, [Section 3](https://arxiv.org/pdf/0806.0837)).

## Experimental status and reproduction

The local demonstration is
[`examples/programmatic/permutation_bootstrap.py`](../examples/programmatic/permutation_bootstrap.py).
The regression coverage is in `fteproxy/tests/` and is run with:

```bash
python -m pytest fteproxy/tests/ -v
```

It exercises fragmentation, authentication, challenge/confirmation,
directional keys, and application records. Negative cases cover tampering,
wrong keys, truncation, framing, mode or negotiation mismatches, zero capacity,
and the scan bound. These are functional checks, not latency benchmarks or
evidence of steganographic security.

## Operational boundaries

The API supports blocking sockets with one reader and one writer operating
concurrently. It is not a nonblocking or selector-aware transport. A handshake
timeout closes the connection after five seconds, or the caller's shorter
socket timeout. After negotiation, a receive timeout preserves partial data
for the next `recv`; EOF inside a record and invalid complete records close
the connection. A failed write is terminal because some ciphertext may
already have reached the peer.

Every PSK holder is trusted to supply regexes. Authentication happens before
compilation, but even a short regex can consume substantial DFA construction
time or memory. There is no compiler sandbox, and the network deadline cannot
interrupt native compilation. Replaying an initial batch can still elicit a
fresh acknowledgement and consume resources. The handshake does not provide
forward secrecy or active-probing resistance.
