# fteproxy performance analysis

Companion to [`benchmark.py`](benchmark.py). Everything below was measured
unless marked *estimated*.

**What was measured**

| | |
|---|---|
| commit | `7093571` (fteproxy 1.0.0) |
| definitions | release `20260903` — `http`, `ftp`, `smtp`, `sip`, `dns` |
| default configuration | format `http`, mode `hybrid` (both directions variable length, 200–700 B) |
| machine | Apple M3 Pro, 12 cores, 36 GB, macOS 26.6.2 (arm64) |
| interpreter | CPython 3.12.14, `fte` 0.4.0, `cryptography` OpenSSL backend |
| date | 2026-09-03, loopback only |

Reproduce:

```bash
uv run python benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --baseline
uv run python benchmark.py --scenarios lan --sizes 64K 1M --repeat 3 --format smtp --mode format
uv run python benchmark.py --scenarios lan --sizes 64K 1M --repeat 3 --format dns  --mode format
uv run python benchmark.py --baseline          # the six shaped scenarios
```

Latency and setup are `benchmark.py`'s own p50 over 50 and 20 samples; a
throughput cell is the best of `--repeat 3` transfers, and the p50/range below
is across three whole runs of the command. The record-layer figures come from a
standalone script (not in the repo) that drives `fteproxy._session_channel`
with random session keys and no sockets, reporting the median of 20–60
encode+decode round trips.

---

## TL;DR

1. **On any real-world link (≤ ~25 Mbit) fteproxy is as fast as raw TCP.** That
   has been true since 0.3 and is unchanged: the network is the bottleneck and
   FTE is invisible. Everything below is about LAN/datacenter-speed links and
   interactive latency.
2. **On the shipped default the per-record cost is one 700-byte covertext:
   1.24 ms in the record layer, and that one number sets everything else.**
   A 64 B round trip costs 2.5 ms (two such records); bulk runs at 166 MB/s
   through the record layer at the relay's 256 KiB record size, and the relay
   gets ~1.1 Gbit/s of 8 MB echo out of it against ~5.9 Gbit/s for plain TCP.
3. **That cost is a property of the format's length, not of the mode.** An FTE
   covertext gets more expensive faster than linearly in its length: the same
   code ranks a 200-byte `http-request` in 0.165 ms and a 700-byte one in
   1.24 ms. `http` is variable length 200–700 and every `hybrid` header is
   sealed at its **max**, so the default pays the top of that curve on every
   record. Picking a format with a shorter maximum is the single biggest
   throughput lever available today without a code change: the same 1 MiB
   record costs 2.31 ms with an `http` header and 1.22 ms with an `smtp` one.
4. **`format` mode (every byte in the target format) is interactive-only:**
   *better* RTT than the default (0.42 ms on `smtp`, 0.61 ms on `dns`, against
   2.5 ms on `http`/hybrid, because those formats' covertexts are short) and
   2.5–4 Mbit/s of bulk. Its bulk cost is inherent to the mode: the DFA runs on
   every covertext, which carries 7–168 bytes on `smtp` and 9–141 on `dns`.
5. **Four of the five shipped formats run in `format` mode by design, so point 4
   is their normal operating point.** `http` is `mode_hint: hybrid` (an HTTP
   message with a raw body is what HTTP looks like); the line protocols `ftp`,
   `smtp`, `sip` and the binary `dns` are `mode_hint: format`, because a line
   protocol has no place to put a high-entropy tail. Expect **0.3–0.5 MB/s**
   and sub-millisecond added latency on those four — fine for a shell, a chat,
   or SOCKS-proxied browsing of text, and not a bulk-transfer channel.
6. **A DFA is compiled per (pattern, length) and then cached for the life of
   the process.** One compile costs 2.4–10.8 ms for `http` and 2.8–5.4 ms for
   `dns`, growing with the length; a variable-length format needs one per
   length it may emit (eight), per direction. The client pre-compiles its
   format's sixteen at startup (121 ms for `http`); **the server does not**, so
   its first connection pays them. First connection vs steady state, measured
   end to end: 18.0 vs 10.4 ms on the default, 68.0 vs 3.5 ms on `dns` in
   `format` mode.
7. **The relay's `select`+throttle poll loop is unchanged** and still carries
   the caveats from 0.3: do not delete the throttle, and a dropped link can
   still wedge an application connection (see *Resilience*).

---

## Measured data (LAN, loopback)

Round-trip echo through both relays, p50 (range) across three runs.

| metric | plain TCP | **`http` hybrid (default)** | `smtp` format | `dns` format |
|---|---:|---:|---:|---:|
| connection setup p50 | – | **10.0 ms** (10.0–10.0) | 2.8 ms (2.5–3.5) | 3.4 ms (3.4–3.6) |
| RTT 64 B p50 | 0.20 ms (0.16–0.22) | **2.52 ms** (2.51–2.59) | 0.42 ms (0.41–0.53) | 0.61 ms (0.60–0.64) |
| RTT 64 B p90 | 0.25 ms | **2.71 ms** | 0.51 ms | 0.75 ms |
| 64 KiB echo | 981 Mbit/s (828–1337) | **53 Mbit/s** (52–54) | 2.66 Mbit/s (2.41–2.73) | 1.68 Mbit/s (1.65–1.69) |
| 1 MiB echo | 5980 Mbit/s (5476–6520) | **574 Mbit/s** (546–595) | 4.12 Mbit/s (3.91–4.24) | 2.54 Mbit/s (2.50–2.63) |
| 8 MiB echo | 5899 Mbit/s (5874–6177) | **1119 Mbit/s** (1117–1130) | – | – |

**Read the small-transfer rows carefully.** `benchmark.py` opens a fresh
tunnelled connection per transfer, so every throughput cell includes one
connection setup. On the default, one setup on its own costs 10.0 ms and the
whole 64 KiB window is 9.8 ms: that row is a *setup* measurement wearing a
throughput row's clothes, which is why it sits below the 1 MiB row. Netting the measured setup
out of the 8 MiB run leaves ~50 ms for 8 MiB of echo, or **~1.34 Gbit/s of
steady-state bulk** (*derived*), which is within 4% of the record layer's own
256 KiB ceiling below — the relay is delivering essentially all of what the
record layer can produce.

One-directional upload (`--direction upload --sizes 8M`) reads 2071 Mbit/s
(1733–2190) against 10107 Mbit/s (8183–10381) for plain TCP, but it stops the
clock when the application's last `send()` returns rather than on delivery, so
it measures the socket buffer as much as the tunnel. The echo rows are the
honest ones.

On the shaped links (`broadband` 25 Mbit and slower) fteproxy matches plain TCP
within measurement noise, as it did on 0.3; those rows are omitted.

### Record layer alone (no sockets), shipped `http` in `hybrid` mode

Median encrypt+decrypt round trip through `fteproxy.record_layer`, one record
per row, p50 (range) over three runs. The header is one sealed `http-request`
covertext at the format's max length, 700 bytes.

| message | ms/record | MB/s | wire bytes | expansion |
|---|---:|---:|---:|---:|
| 64 B | 1.25 (1.24–1.31) | 0.05 | 793 | 12.4x |
| 4 KiB | 1.25 (1.25–1.29) | 3.1 | 4825 | 1.18x |
| 256 KiB (the relay's record size) | 1.51 (1.46–1.56) | 166 (160–171) | 262873 | 1.003x |
| 1 MiB (the body cap) | 2.31 (2.19–2.35) | 433 (425–456) | 1049305 | 1.001x |

Split of one record: the 700-byte header costs **1.20 ms** (0.66 to seal,
0.54 to open) and does not depend on the payload; the AE body costs 0.24 ms per
256 KiB and 0.91 ms per MiB round trip (~1.1 GB/s). So the header is 79% of a
relay-sized record and 52% of a maximal one.

### Record layer alone, `format` mode, per covertext length

Every record is one covertext; the encoder picks the length per record
(`VariableLength.choose_length`), so a stream's cost is a mix of these rows —
biased long when a lot is queued, short when the payload fits in one record.

`http-request` (also the shape of the `hybrid` header, whose row is the last one):

| covertext length | 200 | 271 | 343 | 414 | 486 | 557 | 629 | 700 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| payload per record (B) | 50 | 105 | 160 | 215 | 270 | 325 | 380 | 435 |
| ms per record (encode+decode) | 0.165 | 0.263 | 0.383 | 0.531 | 0.684 | 0.847 | 1.034 | 1.241 |
| MB/s | 0.29 | 0.38 | 0.40 | 0.39 | 0.38 | 0.37 | 0.35 | 0.33 |
| wire expansion | 4.00x | 2.58x | 2.14x | 1.93x | 1.80x | 1.71x | 1.66x | 1.61x |

`dns-request` (a `length-prefix` format: the cipher runs at length − 2):

| covertext length | 90 | 116 | 142 | 168 | 194 | 220 | 246 | 272 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| payload per record (B) | 9 | 28 | 47 | 66 | 84 | 103 | 122 | 141 |
| ms per record (encode+decode) | 0.084 | 0.111 | 0.137 | 0.170 | 0.197 | 0.229 | 0.263 | 0.296 |
| MB/s | 0.10 | 0.24 | 0.33 | 0.37 | 0.41 | 0.43 | 0.44 | 0.45 |
| wire expansion | 10.0x | 4.14x | 3.02x | 2.55x | 2.31x | 2.14x | 2.02x | 1.93x |

The byte rate is flat within about 1.4x across `http`'s range and rises with
length on `dns`, so **which length a record picks is not a throughput
decision** — it is a realism decision, which is what the weighting in
`choose_length` is for. What the length *does* decide is the per-record
latency, and that is why `http`'s 700-byte maximum is the default's headline
cost. Encode-side only, for comparison with the historical table below:
`http-request` runs 0.081 ms/record (0.59 MB/s) at length 200 and
0.676 ms/record (0.61 MB/s) at 700.

### The first record at each length: DFA compile

`fteproxy._regex_format` is an `lru_cache` on `(pattern, length)` holding 1024
entries, so a given length compiles once per process and every later record at
that length gets the tables for free. Cold compile, p50 over three runs:

| length | `http` | `dns` |
|---|---:|---:|
| shortest | 2.37 ms (at 200) | 2.84 ms (at 90) |
| middle | 5.36 ms (at 414) | 3.77 ms (at 168) |
| longest | 10.79 ms (at 700) | 5.35 ms (at 272) |
| all eight | 50.0 ms | 32.0 ms |

So the *first* record at a new length costs the compile plus the record —
about 12.0 ms for `http` at 700 against 1.24 ms thereafter, and 5.6 ms for
`dns` at 272 against 0.30 ms — and the keyed `fte.FTE` built on top of a cached
DFA costs 0.003 ms, which is why a connection can afford to build all eight up
front in `record_layer.VariableLength`.

Standing up both directions of one connection, cold cache vs warm:

| | cold | warm |
|---|---:|---:|
| `http`, hybrid (2 DFAs) | 23.1 ms | 0.010 ms |
| `http`, format (16 DFAs) | 117.7 ms | 0.080 ms |
| `dns`, format (16 DFAs) | 70.3 ms | 0.064 ms |
| `smtp`, format (16 DFAs) | 14.6 ms | 0.065 ms |

The client pays this at startup, in `cli.check_format`: 121 ms for `http`,
226 ms for `sip`, 68 ms for `dns`, 14.5 ms for `smtp`, 7.9 ms for `ftp`
(545 ms for all five, which is what `defs-check` costs). **The server pre-warms
nothing**, so its first connection pays instead. Measured end to end (a fresh
server and client, timing the genuinely first tunnelled connection), first vs
steady state: 18.0 vs 10.4 ms on the default, 20.2 vs 3.2 ms on `smtp`/format,
and **68.0 vs 3.5 ms on `dns`/format**. The two `format`-mode gaps are the
sixteen compiles above almost exactly (64.5 ms and 17.0 ms observed against
64.0 ms and 14.6 ms of compiles); the default's 7.6 ms gap is smaller than its
two 700-byte compiles measured in isolation, so some of that cost is evidently
paid more cheaply in a process that has not just had its cache cleared.

---

## Where the time goes (default: `http`, `hybrid`)

```
app → [client relay] ──FTE──→ [server relay] → dest
        worker thread pair         worker thread pair
        _FTESocketWrapper.send     _FTESocketWrapper.recv
        = record_layer.Encoder     = record_layer.Decoder
          per record:                per record:
          1 sealed 700 B header      1 header rank+verify   1.20 ms the pair
            (DFA unrank, AE)         + body HMAC + AES-CTR  0.91 ms/MiB the pair
          + body AES-CTR + HMAC
```

- A record is one 700-byte formatted header plus a raw body. The relay hands at
  most `2**18` bytes to `send()` per read (`network_io.recvall_from_socket`), so
  records are ≤ 256 KiB and each pays one 1.20 ms header — **79% of a
  relay-sized record**, or 4.8 ms per MiB of goodput. The 1 MiB body cap is
  never reached in the relay.
- **The header's cost is the seal, not the payload it carries.** A hybrid header
  carries four bytes (the body length), but `_seal` pads the plaintext to the
  format's full 448-byte capacity before encrypting, because a short message
  ranks low and unranks into a degenerate covertext (see the seal-padding rule
  in `docs/format-authoring.md`). Encrypting 16 bytes at length 700 costs
  0.11 ms; encrypting the padded 448 costs 0.66 ms. Realism is buying that 6x,
  and it is not optional.
- **Covertext cost grows faster than linearly with length**: 0.83 µs per
  covertext byte at length 200, 1.77 µs at 700. This is why the default is
  slower than a format with a smaller maximum, and why nothing in the
  variable-length machinery changes the byte rate much.
- **A new length costs one DFA compile, once per process** (2.4–10.8 ms on
  `http`, 2.8–5.4 ms on `dns`), and nothing thereafter: the tables are cached on
  `(pattern, length)` and shared read-only by every connection and thread. The
  set of lengths is small (eight) precisely because of this; a continuous range
  would be one compile per byte. The client compiles its format's sixteen at
  startup, the server on demand, so a *server*'s first connection is 2–19x its
  steady-state setup.
- Interactive traffic: one 64 B message costs one 700-byte header plus a 93-byte
  body — 793 B on the wire, **12.4x expansion**, and 1.25 ms of CPU per
  direction. In `format` mode the same message is one covertext: 271 B and 0.26 ms on `http` (the shortest length that holds 64 bytes; a
  200-byte covertext carries only 50), 183 B and about 0.13 ms on `smtp`.
- Sealing's random pad (`os.urandom`), per-record `Cipher` construction, buffer
  concatenation and the body/remainder slices are each under 1% of a record.
- In `format` mode every covertext is one DFA rank/unrank, so the payload per
  rank is 50–435 bytes on `http`, 7–168 on `smtp` and 9–141 on `dns` — the
  2.5–4 Mbit/s in the table above.

---

## Improvements landed in 1.0

1. **Hybrid record layer with an OpenSSL AE body** (the redesign): the DFA runs
   once per record instead of once per 50–435 bytes, and the body itself moves at
   ~1.1 GB/s round trip. On the shipped `http` format that is 166 MB/s at the
   relay's record size against 0.32 MB/s for the same format in `format` mode.
2. **Cipher cache**: the expensive half of a libfte cipher is the DFA, and
   `_regex_format` memoizes it on `(pattern, length)`, so a cached cipher costs
   0.003 ms to build instead of 2.4–10.8 ms. Without it every connection — and
   every candidate in the server's first-record scan — would recompile. The
   keyed `fte.FTE` on top is built per session, because since 1.0 every
   connection derives its own keys. A connection builds its eight ciphers per
   direction up front in `record_layer.VariableLength` rather than one per
   record.
3. **A pending header is decrypted once.** A 256 KiB record arrives in ~3 reads;
   the decoder used to re-rank and re-verify the same header on each partial
   delivery. With a 1.20 ms header that would now cost more than double.
4. **A peer that closes before handshaking gets EOF** instead of being polled
   forever. Without this, one dead connection (a port scan, a health check, an
   active probe) cost 64% of a core.
5. **The handshake moved off the relay workers.** A per-connection setup thread
   completes it, reads the client's OPEN and dials the destination before either
   worker starts, so the accept loop no longer waits on a `connect()` and the
   two workers never touch a half-built encoder. That was the precondition for
   reworking the poll loop (lever #2 below).
6. Carried over from 0.3: `TCP_NODELAY` on both relay hops, O(n) buffer handling
   in the record layer, and trying the most-recently-matched format first in the
   server's first-record scan.

Connection setup on the default is 10.0 ms, and it is records rather than
crypto: five covertext round trips (client hello, server hello, OPEN,
OPEN_RESULT, the first data record) at ~1.2 ms each account for ~6.2 ms of it,
against 0.31 ms for both X25519 key generations and the exchange; the rest is
the two TCP dials, the setup thread and the server's first-record scan. The
same handshake on `smtp` costs 2.8 ms — the difference is the covertext
length.

## Remaining levers, ranked by impact ÷ effort

1. **Shorten what a `hybrid` header is sealed at** (small effort, wire change).
   Hybrid formats only the header, and the header exists to carry a 4-byte
   length, yet it is sealed at the format's *maximum* (700 B on `http`) because
   that is where the handshake seals. Sealing hybrid headers at the format's
   *shortest* length instead would take the per-record cost from 1.20 ms toward
   0.165 ms — roughly 4x on bulk and 6x on interactive latency — at the cost of
   a fixed short covertext
   in a stream whose bodies are already high-entropy. Measured today by
   substituting a shorter format's header: a 1 MiB record costs 2.31 ms with
   `http`'s 700-byte header, 1.22 ms with `smtp`'s 320-byte one (818 MB/s), and
   1.30 ms with `dns`'s 272-byte one.
2. **Rework the polling relay loop** (large effort; fixes idle CPU, a latency
   ripple, and the hang on link drop). The 0.3 caveat stands: simply deleting
   `time.sleep(throttle)` in `worker.run()` regressed the real subprocess
   deployment ~13x when it was tried (a GIL-scheduling convoy between the two
   workers), and on 0.3 a naive blocking-`recv` rework raced the in-band
   negotiation between the two workers. 1.0 removes that second obstacle — the
   handshake now finishes on a setup thread before either worker starts — so
   what is left is the GIL convoy, and the shape to try is one `selectors` loop
   per connection handling both directions. Not re-measured in this run; still
   not a drive-by.
3. **Pre-warm the server's DFAs at startup** (small effort, no wire change). The
   client already does this in `cli.check_format`; the server compiles on its
   first connection instead, which costs that connection 18.0 ms on the default
   and 68.0 ms on `dns` in `format` mode, against 10.4 ms and 3.5 ms once
   warm. The server cannot know which format a
   client will pick, so the honest version is to compile the whole catalog —
   545 ms of startup for all five formats at all lengths, both directions.
4. **Carry small messages inline in the sealed header** (medium effort). A
   message of ≤ 435 bytes fits in the header's capacity, so it could travel as
   one covertext instead of header + body. On its own that is 12.4x → 10.9x
   expansion for a 64 B interactive message at no extra CPU (the header is
   already sealed at full capacity, so the payload rides for free); combined
   with lever #1 the same message becomes one 271-byte covertext — 4.2x and
   0.26 ms instead of 793 B and 1.25 ms.
5. **AES-GCM for the body** would cut body CPU (*estimated*), but the body is
   16% of a 256 KiB record and the header is 79%. Not worth a wire change today.
6. **`format` mode throughput is inherent** to transforming every byte; the only
   lever is a faster ranker (a C extension releasing the GIL).

---

## Resilience — link dropped mid-transfer

Unchanged from 0.3, and still real: when a bidirectional application's link is
cut, the relay usually frees the app within ~0.5 s, but in a minority of runs a
worker blocked in `sendall` to one peer never checks its other peer and the
connection wedges past the observation window. The nominal 30 s
`runtime.fteproxy.relay.socket_timeout` cannot rescue it because the poll loop
never issues a blocking `recv` that lasts long enough. Lever #2 above is the
fix. (`benchmark.py --resilience`; not re-run for this revision.)

What is new since 0.3 is that the *other* stuck states are fixed: a connection
closed before the handshake, and one that opens and then falls silent, both
release their worker — the first at EOF, the second at the handshake deadline.

---

## What did *not* turn out to be a problem

- **Slow, high-latency or low-bandwidth links.** fteproxy matches raw TCP there.
- **Random padding.** `os.urandom` for the seal pad is 2 µs of a 660 µs header.
  What costs is encrypting the pad, not generating it.
- **The 1 MiB body cap.** Never reached; records are bounded by the relay's read
  size.
- **Cell/buffer size tuning.** As on 0.3, `network_io`'s `2**18` read size is
  the right balance; larger buffers trade small-transfer latency for little bulk
  gain — and with a 1.20 ms header, a *smaller* one would cost dearly.
- **Variable length.** The eight-length machinery costs one DFA per length once
  per process and leaves the byte rate flat within ~1.4x. It is the *value* of
  the maximum, not the spread, that costs.

Two entries moved off this list since 0.3.1: **server startup**, which is now
0 ms only because the server defers every compile to its first connection
(lever #3), and **the format's length**, which was a fixed 256 bytes in the old
shape catalog and is now 700 on the default.

---

## Historical: 0.3.1 and the old shape catalog

These numbers are **not current** and are kept only for the comparison they
support. They were taken on 2026-09-02 on the same machine (then on CPython
3.14.7) against `manual-http-request`/`-response` from the release `20260110`
shape catalog — a *fixed* 256-byte covertext — before the five-protocol
definitions release made `http` variable length 200–700.

| metric | plain TCP | 0.3.1 (`fte` 0.3.0) | 1.0 hybrid, 256 B format | 1.0 format, 256 B |
|---|---:|---:|---:|---:|
| connection setup p50 | – | 2.7–3.3 ms | 1.1 ms | ~1 ms |
| RTT 64 B p50 | 0.15 ms | 1.5–1.7 ms | 0.51 ms | 0.73 ms |
| 1 MB echo | 2596 Mbit/s | 452–522 Mbit/s | 2540 Mbit/s | 7.3 Mbit/s |
| 8 MB echo | 6071 Mbit/s | 655–700 Mbit/s | 4626 Mbit/s | – |
| record layer, 256 KiB | – | 75–88 MB/s | 657–713 MB/s | 0.9–1.8 MB/s |
| record layer, 1 MiB | – | 75–89 MB/s | 920–960 MB/s | 1.0–1.8 MB/s |
| per-record fixed cost | – | ~0.9 ms | ~0.17 ms | – |

The 5–7x bulk win and 3x latency win the 1.0 record layer took from 0.3.1 are
real and still in the code; what changed underneath them is the covertext the
default seals at. The old ~0.17 ms per-record figure and today's 1.24 ms are the
same operation on the same code: a sealed `http`-shaped covertext at 256 bytes
versus one at 700. The per-length table above reproduces it — 0.165 ms at
length 200 — which is the cleanest evidence that the regression against these
historical rows is the format's length and nothing else.
