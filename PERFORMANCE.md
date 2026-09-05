# fteproxy performance analysis

Companion to [`benchmark.py`](benchmark.py). Everything below was measured
unless marked *estimated*.

**What was measured**

| | |
|---|---|
| commit | `34b6def` (fteproxy 1.0.0) |
| definitions | release `20260903` — `http`, `ftp`, `smtp`, `sip`, `dns` |
| measured default configuration | format `http`, mode `hybrid` (200 B base-regex header + raw body; superseded) |
| machine | Apple M3 Pro, 12 cores, 36 GB, macOS 26.6.2 (arm64) |
| interpreter | CPython 3.12.14, `fte` 0.4.0, `cryptography` 50.0.1 (OpenSSL backend) |
| date | 2026-09-03, loopback only |

The measurements at commit `34b6def` predate the HTTP carrier-framing
correction. Current HTTP hybrid records use a separate
`Transfer-Encoding: chunked` header and wrap the same encrypted body in one
chunk plus the terminal zero chunk. The body wrapper adds no additional DFA or
cryptographic pass and only `len(format(B, "x")) + 9` wire bytes for a
non-empty body of `B` bytes (14 bytes at the relay's 256 KiB payload size). The header does use
a different DFA, however, so the timing tables below are a pre-correction
reference, not a measurement of the final path; claims about the added framing
bytes are derived. Re-run the benchmark before quoting final header latency or
sub-percent wire rates.

All measurements use a direct, byte-preserving TCP path. Passing this carrier
through an HTTP intermediary is unsupported: header rewriting or
dechunking/rechunking breaks the tunnel. The benchmark also does not measure
HTTP semantic realism. Request and response records are generated independently
and need not form balanced or correlated transactions.

Reproduce:

```bash
uv run python benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --baseline
uv run python benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --format smtp --mode format
uv run python benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --format dns  --mode format
```

Latency and setup are `benchmark.py`'s own p50 over 50 and 20 samples; a
throughput cell is the best of `--repeat 3` transfers, and the p50/range below
is across three whole runs of the command. The record-layer figures come from a
standalone script (not in the repo) that drives `fteproxy._session_channel`
with random session keys and no sockets, reporting the median of 30–200
encode+decode round trips, again p50/range across three runs.

One gotcha worth knowing before reading the *setup* row: `benchmark.py` waits
for the client's forward port by connecting to it, and that connection already
builds a tunnel, so everything the script reports is **steady state**. The
cold-server numbers in *DFA warm-up* come from a separate probe that waits on a
timer instead.

---

## TL;DR

1. **On any real-world link (≤ ~25 Mbit) fteproxy is as fast as raw TCP.** That
   has been true since 0.3 and is unchanged: the network is the bottleneck and
   FTE is invisible. Everything below is about LAN/datacenter-speed links and
   interactive latency.
2. **In the pre-correction measurement, the default's 200-byte covertext cost
   0.162 ms for the header pair.** A 64 B round trip cost 0.50 ms end to end;
   bulk ran at 612 MB/s through the record layer at the relay's 256 KiB payload
   size, and the relay got 3.5 Gbit/s of 8 MiB echo against 5.8 Gbit/s for plain
   TCP — 5.0 Gbit/s once the one connection setup each transfer paid was
   netted out (*derived*). The final chunked header DFA needs remeasurement.
3. **The single biggest change since the last revision is where a hybrid
   header is sealed.** It used to go out at the format's `max_length` (700 B on
   `http`); it now goes out at the shortest length whose cipher holds the
   16-byte header — 200 B on `http`. Covertext cost grows faster than linearly
   with length; on the measured pre-correction regex that took 7.4x off the
   per-record cost (1.20 ms → 0.162 ms), 5.0x off interactive latency and 3.1x
   on 8 MiB bulk. The final hybrid regex keeps the 200-byte choice but needs a
   new timing. See *Historical* for the measured side-by-side.
4. **The body was the larger half of a bulk record in that measurement**: 58%
   of the compute time for a 256 KiB payload against the header's 38%. The
   corrected path needs remeasurement before assigning final percentages.
5. **`format` mode (every byte in the target format) is interactive-only:**
   comparable RTT to the default (0.49 ms on `smtp`, 0.66 ms on `dns`, against
   0.50 ms on `http`/hybrid) and 2.7–5.0 Mbit/s of bulk. That cost is inherent to
   the mode: the DFA runs on every covertext, which carries 7–168 bytes on
   `smtp` and 9–141 on `dns`.
6. **Four of the five shipped formats run in `format` mode by design, so point
   5 is their normal operating point.** `http` is `mode_hint: hybrid`: its
   handshake and format-mode grammar describes a complete zero-body message,
   while its hybrid grammar advertises a body on `POST` requests and
   body-permitted responses with `Transfer-Encoding: chunked`. The line
   protocols `ftp`, `smtp`, `sip` and the binary `dns` are `mode_hint: format`,
   because a line or self-delimiting protocol has no place to put a
   high-entropy tail. Expect **0.4–0.6 MB/s** and sub-millisecond added latency
   on those four — fine for a shell, a chat, or SOCKS-proxied browsing of text,
   and not a bulk-transfer channel.
7. **A DFA is compiled per (pattern, length) and then cached for the life of
   the process.** Loading the definitions compiles every format's `max_length`
   at startup (165 ms, both ends); the *other* lengths are compiled on demand,
   which is why a server's first connection costs 34.7 ms on the default and
   82 ms on `dns`/`format` against 3–6 ms once warm.
8. **The relay's `select`+throttle poll loop is unchanged** and still carries
   the caveats from 0.3: do not delete the throttle, and a dropped link can
   still wedge an application connection (see *Resilience*).

---

## Measured data (LAN, loopback)

Round-trip echo through both relays, p50 (range) across three runs.

| metric | plain TCP | **`http` hybrid (default)** | `smtp` format | `dns` format |
|---|---:|---:|---:|---:|
| connection setup p50 | – | **5.7 ms** (5.7–5.8) | 3.8 ms (3.6–4.3) | 4.2 ms (4.0–4.4) |
| RTT 64 B p50 | 0.13 ms (0.12–0.16) | **0.50 ms** (0.49–0.51) | 0.49 ms (0.48–0.50) | 0.66 ms (0.66–0.70) |
| RTT 64 B p90 | 0.23 ms | **0.59 ms** | 0.65 ms | 0.87 ms |
| 64 KiB echo | 452 Mbit/s (425–482) | **101 Mbit/s** (100–101) | 2.98 Mbit/s (2.86–3.00) | 1.82 Mbit/s (1.80–2.00) |
| 1 MiB echo | 2838 Mbit/s (2147–3247) | **1162 Mbit/s** (1159–1164) | 4.28 Mbit/s (4.28–4.35) | 2.73 Mbit/s (2.71–2.74) |
| 8 MiB echo | 5803 Mbit/s (5330–6088) | **3511 Mbit/s** (3425–3533) | 4.98 Mbit/s (4.95–5.08) | 3.24 Mbit/s (3.22–3.26) |

**Read the small-transfer rows carefully.** `benchmark.py` opens a fresh
tunnelled connection per transfer, so every throughput cell includes one
connection setup. On the default one setup costs 5.7 ms and the whole 64 KiB
window is 5.2 ms: that row is a *setup* measurement wearing a throughput row's
clothes, which is why it sits so far below the 1 MiB row. Netting the measured
setup out of the 8 MiB run leaves ~13.4 ms for 8 MiB of echo, or **~5.0 Gbit/s
of steady-state bulk** (*derived*) — 86% of what plain TCP does over the same
loopback, and more than one thread of the record layer can produce, because the
two directions and the two processes overlap.

On the shaped links (`broadband` 25 Mbit and slower) fteproxy matches plain TCP
within measurement noise, as it did on 0.3; those rows are omitted.

### Record layer alone (no sockets), pre-correction `hybrid` mode

Median encrypt+decrypt round trip through `fteproxy.record_layer`, one record
per row, p50 (range) over three runs. The header is one sealed covertext at
`fteproxy.hybrid_header_length` — 200 bytes on `http`, 80 on `smtp`.

The pre-correction `http` carrier (200-byte base-regex header, raw body):

| message | ms/record | MB/s | wire bytes | expansion |
|---|---:|---:|---:|---:|
| 64 B | 0.173 (0.172–0.173) | 0.37 | 293 | 4.58x |
| 4 KiB | 0.179 (0.178–0.180) | 22.8 | 4325 | 1.06x |
| 256 KiB (the relay's record size) | 0.428 (0.427–0.429) | 612 (610–614) | 262373 | 1.0009x |
| 1 MiB (the body cap) | 1.156 (1.127–1.172) | 907 (895–931) | 1048805 | 1.0002x |

`smtp` (80-byte header), a short-header format for contrast (`ftp`'s reply
direction is shorter still, at 64):

| message | ms/record | MB/s | wire bytes | expansion |
|---|---:|---:|---:|---:|
| 64 B | 0.076 (0.075–0.077) | 0.84 | 173 | 2.70x |
| 4 KiB | 0.081 (0.081–0.081) | 50.5 | 4205 | 1.03x |
| 256 KiB | 0.329 (0.328–0.330) | 797 (794–800) | 262253 | 1.0004x |
| 1 MiB | 1.053 (1.009–1.055) | 996 (994–1040) | 1048685 | 1.0001x |

In that measurement, the 200-byte `http` header cost **0.162 ms** (0.083 to
seal, 0.079 to open) and did not depend on the payload; the AE body cost 0.250
ms per 256 KiB and 0.959 ms per MiB round trip (~1.05 GB/s). The header was 38%
of a relay-sized record and 14% of a maximal one, and the two formats' 256 KiB
rows differed by exactly their header pair (0.162 vs 0.064 ms). Current HTTP
uses a different hybrid-header regex and adds chunk framing, so those timing
shares are reference values only.

### Record layer alone, `format` mode, per covertext length

Every record is one covertext; the encoder picks the length per record
(`VariableLength.choose_length`), so a stream's cost is a mix of these rows —
biased long when a lot is queued, short when the payload fits in one record.

`http-request` (the base format-mode shape; the current hybrid header uses its
separate `hybrid_regex`, so this table does not measure that header):

| covertext length | 200 | 271 | 343 | 414 | 486 | 557 | 629 | 700 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| payload per record (B) | 50 | 105 | 160 | 215 | 270 | 325 | 380 | 435 |
| ms per record (encode+decode) | 0.158 | 0.255 | 0.378 | 0.508 | 0.663 | 0.843 | 1.028 | 1.249 |
| MB/s | 0.32 | 0.41 | 0.42 | 0.42 | 0.41 | 0.39 | 0.37 | 0.35 |
| wire expansion | 4.00x | 2.58x | 2.14x | 1.93x | 1.80x | 1.71x | 1.66x | 1.61x |

`dns-request` (a `length-prefix` format: the cipher runs at length − 2):

| covertext length | 90 | 116 | 142 | 168 | 194 | 220 | 246 | 272 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| payload per record (B) | 9 | 28 | 47 | 66 | 84 | 103 | 122 | 141 |
| ms per record (encode+decode) | 0.076 | 0.101 | 0.127 | 0.158 | 0.186 | 0.217 | 0.252 | 0.290 |
| MB/s | 0.12 | 0.28 | 0.37 | 0.42 | 0.45 | 0.47 | 0.48 | 0.49 |
| wire expansion | 10.0x | 4.14x | 3.02x | 2.55x | 2.31x | 2.14x | 2.02x | 1.93x |

The byte rate is flat within about 1.3x across `http`'s range and rises with
length on `dns`, so **which length a record picks is not a throughput
decision** — it is a realism decision, which is what the weighting in
`choose_length` is for. What the length *does* decide is the per-record
latency. Encode-side only, for comparison with the historical table below:
`http-request` runs 0.079 ms/record (0.63 MB/s) at length 200 and
0.672 ms/record (0.65 MB/s) at 700.

**Cost per covertext byte is superlinear in the length**: 0.79 µs at length 200
against 1.78 µs at 700 for the round trip, 0.40 µs against 0.92 µs for the seal
alone. That curve is the whole reason the hybrid header moved (below), and the
reason a format with a long maximum is expensive in `format` mode.

### The first record at each length: DFA compile

`fteproxy._regex_format` is an `lru_cache` on `(pattern, length)` holding 1024
entries, so a given length compiles once per process and every later record at
that length gets the tables for free. Cold compile, p50 over three runs:

| length | `http` | `dns` |
|---|---:|---:|
| shortest | 2.38 ms (at 200) | 2.85 ms (at 90) |
| middle | 5.02 ms (at 414) | 3.61 ms (at 168) |
| longest | 9.86 ms (at 700) | 5.03 ms (at 272) |
| all eight | 46.2 ms | 30.7 ms |

So the *first* record at a new length costs the compile plus the record —
about 2.5 ms for `http` at 200 against 0.16 ms thereafter — while a cached
lookup is 0.0005 ms and the keyed `fte.FTE` built on top of a cached DFA is
0.006–0.019 ms, which is why a connection can afford to build all eight up
front in `record_layer.VariableLength`.

### DFA warm-up: what each process pays, and when

Loading the definitions compiles one DFA per entry at its `max_length` — that
is `check_capacities`, which proves every shipped format can carry a handshake
— so **both** ends already hold the lengths the handshake seals at before any
connection arrives. In a fresh process: `import fteproxy` 14 ms, the first
`load_definitions()` **165 ms**. Building the first session channel *after*
that, which is what a server's first connection adds:

| | cold | warm |
|---|---:|---:|
| `http`, hybrid (2 header DFAs at 200) | 6.0 ms | 0.024 ms |
| `smtp`, format (16 DFAs) | 21.4 ms | 0.090 ms |
| `dns`, format (16 DFAs) | 67.5 ms | 0.089 ms |
| `http`, format (16 DFAs) | 98.4 ms | 0.116 ms |
| `sip`, format (16 DFAs) | 183.1 ms | 0.110 ms |

The client pre-compiles its format's sixteen at startup in `cli.check_format`
(117 ms for `http`, 221 ms for `sip`, 74 ms for `dns`, 15 ms for `smtp`, 8 ms
for `ftp` from a cleared cache; 484 ms for all five, which is what `defs-check`
costs). Process startup, exec to listening: **server 236 ms**, client 344 ms on
`http`, 403 ms on `sip`, 292 ms on `dns`, 232 ms on `smtp`, 233 ms on `ftp`.

**The server pre-warms only what the definitions load gave it**, so its first
connection pays for the header length and, in `format` mode, for all sixteen.
Measured end to end (a fresh server and client, timing the genuinely first
tunnelled connection — the probe waits on a timer, not by connecting), first vs
steady state:

| | first connection | steady p50 |
|---|---:|---:|
| `http`, hybrid (default) | 34.7 ms (27.9–42.8) | 5.8 ms |
| `smtp`, format | 32.1 ms (30.7–48.6) | 3.1 ms |
| `dns`, format | 82.1 ms (81.2–98.4) | 3.4 ms |
| `sip`, format | 225.4 ms (224.0–227.3) | 7.6 ms |

The `format`-mode gaps are the sixteen compiles above almost exactly (78.7 ms
observed against 67.5 ms of compiles on `dns`, 217.8 against 183.1 on `sip`);
the default's 28.9 ms gap is larger than its 6.0 ms of header compiles, the
rest being one-time cost in a process that has just started — first use of the
AE primitives, the relay's thread and destination dial.

---

## Where the time goes (current layout; pre-correction timings)

```
app → [client relay] ──FTE──→ [server relay] → dest
        worker thread pair         worker thread pair
        _FTESocketWrapper.send     _FTESocketWrapper.recv
        = record_layer.Encoder     = record_layer.Decoder
          per record:                per record:
          1 sealed 200 B header      1 header rank+verify   0.162 ms the pair
            (DFA unrank, AE)         + body HMAC + AES-CTR  0.959 ms/MiB the pair
          + HTTP chunk-size line
          + body AES-CTR + HMAC
          + terminal zero chunk
```

- A record is one 200-byte formatted header, one HTTP chunk containing the
  authenticated body, and the terminal zero chunk. The relay hands at most
  `2**18` bytes of application data to `send()` per read
  (`network_io.recvall_from_socket`). At that maximum the encrypted body is
  256 KiB + 29 bytes, its five-hex-digit chunk framing adds 14 bytes, and the
  complete wire record is 256 KiB + 243 bytes. In the pre-correction
  measurement, one 0.162 ms header was **38% of the compute time for a
  relay-sized record**, or 0.65 ms per MiB of goodput. The final header timing
  has not been measured. The 1 MiB application-payload cap is never reached in
  the relay.
- **The body was the bigger half in that measurement.** AES-CTR + HMAC-SHA256
  took 0.250 ms of a 256 KiB record's 0.428 ms, at ~1.05 GB/s round trip:
  header 38%, body 58%, framing and buffer handling the remaining 4%. Writing
  and checking HTTP's 14 deterministic bytes is expected to fit inside that
  rounding, but the different hybrid-header DFA also needs remeasurement.
- **A hybrid header carries four bytes and is sealed in the shortest covertext
  that holds them.** `hybrid_header_length` measures each allowed length's real
  capacity and takes the first that fits `HYBRID_HEADER_BYTES` = 16: 200 on
  `http`, 300 on `sip`, 90 on `dns`, 91/64 on `ftp` (request/reply), 80 on
  `smtp`. Nothing negotiates it — both ends compute it from the same
  definitions entry.
- **Seal padding is cheap at this length.** `_seal` pads the plaintext to the
  cipher's full capacity so a short message cannot rank low and unrank into a
  degenerate covertext. The measured base regex held 63 bytes at length 200:
  encrypting the bare 16 cost 0.050 ms and the padded 63 cost 0.077 ms, so
  realism cost 1.5x there. The current hybrid request/response regexes hold 40
  and 45 bytes at length 200; their padding cost has not been remeasured. At
  700 the old base regex held 448 bytes and the same rule cost 6x (0.108 ms
  against 0.646).
- **A new length costs one DFA compile, once per process** (2.4–9.9 ms on
  `http`, 2.9–5.0 ms on `dns`), and nothing thereafter: the tables are cached on
  `(pattern, length)` and shared read-only by every connection and thread. The
  set of lengths is small (eight) precisely because of this; a continuous range
  would be one compile per byte.
- Interactive traffic: one 64 B message now costs one 200-byte header, a
  93-byte authenticated body and 11 bytes of chunk framing — 304 B on the wire,
  **4.75x expansion**. Its pre-correction CPU measurement was 0.173 ms per
  direction. In `format` mode the same message is one covertext at the shortest
  length whose capacity holds it (`choose_length` never picks a shorter one):
  271 B and 0.254 ms on `http` (a 200-byte covertext carries only 50 payload
  bytes), 183 B and 0.143 ms on `smtp`, 168 B and 0.155 ms on `dns`.
- Connection setup measured 5.7 ms before the carrier correction, and records
  rather than crypto dominated it: the two hellos were sealed at the format's
  `max_length` (700 B on `http`, 1.25 ms each round trip) because the server has
  to scan for them, and the OPEN, OPEN_RESULT and first data record were hybrid
  records at 0.17 ms — about 3.0 ms of the 5.7 — against 0.31 ms for both X25519
  key generations and the exchange; the rest was the two TCP dials and setup
  thread. The handshake still uses the same zero-body base regex, but the three
  post-handshake records now use the unmeasured chunked header DFA.
- Sealing's random pad (`os.urandom`), per-record `Cipher` construction, buffer
  concatenation and the body/remainder slices are each under 1% of a record.
- In `format` mode every covertext is one DFA rank/unrank, so the payload per
  rank is 50–435 bytes on `http`, 7–168 on `smtp` and 9–141 on `dns` — the
  2.7–5.0 Mbit/s in the table above.

---

## Improvements landed in 1.0

1. **A hybrid header is sealed at the shortest length that holds it, not at
   `max_length`** (`fteproxy.hybrid_header_length`). On the default that is
   200 bytes instead of 700, which is 7.4x off the per-record header cost and
   the largest single win in this release. Full before/after in *Historical*.
2. **Hybrid record layer with an OpenSSL AE body** (the redesign): the DFA runs
   once per record instead of once per 50–435 bytes, and the body itself moves
   at ~1.05 GB/s round trip. On the shipped `http` format that is 612 MB/s at
   the relay's record size against 0.32–0.42 MB/s for the same format in
   `format` mode.
3. **Cipher cache**: the expensive half of a libfte cipher is the DFA, and
   `_regex_format` memoizes it on `(pattern, length)`, so a cached cipher costs
   0.006–0.019 ms to build instead of 2.4–9.9 ms. Without it every connection —
   and every candidate in the server's first-record scan — would recompile. The
   keyed `fte.FTE` on top is built per session, because since 1.0 every
   connection derives its own keys. A connection builds its eight ciphers per
   direction up front in `record_layer.VariableLength`.
4. **A pending header is decrypted once.** A 256 KiB record arrives in ~3 reads;
   the decoder used to re-rank and re-verify the same header on each partial
   delivery.
5. **A peer that closes before handshaking gets EOF** instead of being polled
   forever. Without this, one dead connection (a port scan, a health check, an
   active probe) cost 64% of a core.
6. **The handshake moved off the relay workers.** A per-connection setup thread
   completes it, reads the client's OPEN and dials the destination before either
   worker starts, so the accept loop no longer waits on a `connect()` and the
   two workers never touch a half-built encoder. That was the precondition for
   reworking the poll loop (lever #1 below).
7. Carried over from 0.3: `TCP_NODELAY` on both relay hops, O(n) buffer handling
   in the record layer, and trying the most-recently-matched format first in the
   server's first-record scan.

## Remaining levers, ranked by impact ÷ effort

1. **Rework the polling relay loop** (large effort; fixes idle CPU, a latency
   ripple, and the hang on link drop). The 0.3 caveat stands: simply deleting
   `time.sleep(throttle)` in `worker.run()` regressed the real subprocess
   deployment ~13x when it was tried (a GIL-scheduling convoy between the two
   workers), and on 0.3 a naive blocking-`recv` rework raced the in-band
   negotiation between the two workers. 1.0 removes that second obstacle — the
   handshake now finishes on a setup thread before either worker starts — so
   what is left is the GIL convoy, and the shape to try is one `selectors` loop
   per connection handling both directions. Not re-measured in this run; still
   not a drive-by. With the header at 0.162 ms in the pre-correction
   measurement, this became the largest measured relay-side cost; remeasure the
   final header before ranking it precisely.
2. **A faster body cipher** (medium effort, wire change). The body is 58% of a
   256 KiB record in the pre-correction timing now that the header is 200 bytes,
   so it had overtaken the header as the thing to attack. AES-GCM through the
   same OpenSSL backend would replace CTR + a separate HMAC pass over the same
   bytes (*estimated*); that construction measured 1.05 GB/s round trip.
3. **Pre-warm the server's remaining DFAs at startup** (small effort, no wire
   change). The definitions load already compiles every format's `max_length`
   (165 ms in the measured build); what a server still compiled on its first
   connection was the hybrid header length and, in `format` mode, all sixteen
   — 34.7 ms on the default, 82 ms on `dns`/`format`, 225 ms on `sip`/`format`,
   against 3–6 ms warm. The final HTTP hybrid DFA changes the first number and
   needs remeasurement. The server cannot know which format a client will pick,
   so the honest version remains compiling the whole catalog at startup.
4. **Carry a small message inline in the sealed header** (medium effort). At
   length 200 the current hybrid request grammar has 40 bytes of cipher
   plaintext capacity. After the seal's 12 bytes, the four-byte body length and
   a one-byte record type, at most 23 application bytes could ride inline in
   both directions (the response grammar has slightly more room). A 23-byte
   message currently occupies 263 wire bytes -- a 200-byte header plus a
   52-byte encrypted body and 11 bytes of chunk framing -- so inline carriage
   could reduce it to 200. That is a protocol change and its CPU cost has not
   been measured; the old 50-byte estimate applied to the base regex, not the
   final hybrid grammar.
5. **`format` mode throughput is inherent** to transforming every byte; the only
   lever is a faster ranker (a C extension releasing the GIL).

---

## Resilience — link dropped mid-transfer

Unchanged from 0.3, and still real: when a bidirectional application's link is
cut, the relay usually frees the app within ~0.5 s, but in a minority of runs a
worker blocked in `sendall` to one peer never checks its other peer and the
connection wedges past the observation window. The nominal 30 s
`runtime.fteproxy.relay.socket_timeout` cannot rescue it because the poll loop
never issues a blocking `recv` that lasts long enough. Lever #1 above is the
fix. (`benchmark.py --resilience`; not re-run for this revision.)

What is new since 0.3 is that the *other* stuck states are fixed: a connection
closed before the handshake, and one that opens and then falls silent, both
release their worker — the first at EOF, the second at the handshake deadline.

---

## What did *not* turn out to be a problem

- **Slow, high-latency or low-bandwidth links.** fteproxy matches raw TCP there.
- **Random padding.** `os.urandom` for the seal pad is 0.9 µs of an 83 µs header.
  What costs is encrypting the pad, not generating it. On the measured base
  regex's 63-byte capacity that was 0.027 ms, down from 0.54 ms at its old
  448-byte capacity. The current 200-byte hybrid grammars hold 40/45 bytes and
  have not been timed.
- **The 1 MiB body cap.** Never reached; records are bounded by the relay's read
  size.
- **Cell/buffer size tuning.** As on 0.3, `network_io`'s `2**18` read size is
  the right balance; larger buffers trade small-transfer latency for little bulk
  gain. With a 0.162 ms header in the pre-correction measurement a smaller one
  was no longer the catastrophe it was at 700 bytes, but it still bought
  nothing. Re-evaluate only if the final header timing changes materially.
- **Variable length.** The eight-length machinery costs one DFA per length once
  per process and leaves the byte rate flat within ~1.3x. It is the *value* of
  the length a record seals at, not the spread, that costs — which is exactly
  what the hybrid-header change acted on.
- **The format's maximum length, for the default.** It was on this list's
  opposite side one revision ago (see below) and is now confined to the
  handshake's two records and to `format` mode.

**Server startup** stays off this list in a qualified way: it is 236 ms, nearly
all of it the definitions load, and the compiles that load does *not* do are
what its first connection pays (lever #3).

---

## Historical: the 700-byte hybrid header (before `34b6def`)

Commit `7093571` was measured on this same machine and definitions release,
immediately before the change, when every hybrid header was sealed at the
format's `max_length`.
It is the most useful comparison in this document, because nothing else changed
between the two: same code path, same formats, same benchmark.

End to end, LAN loopback, p50 across three runs:

| metric | before (700 B header) | after (200 B header) | change |
|---|---:|---:|---:|
| connection setup p50 | 10.0 ms | 5.7 ms | 1.8x |
| RTT 64 B p50 | 2.52 ms | 0.50 ms | 5.0x |
| RTT 64 B p90 | 2.71 ms | 0.59 ms | 4.6x |
| 64 KiB echo | 53 Mbit/s | 101 Mbit/s | 1.9x |
| 1 MiB echo | 574 Mbit/s | 1162 Mbit/s | 2.0x |
| 8 MiB echo | 1119 Mbit/s | 3511 Mbit/s | 3.1x |

Record layer, one `http` hybrid record:

| message | before | after | change |
|---|---:|---:|---:|
| 64 B | 1.25 ms, 793 B, 12.4x | 0.173 ms, 293 B, 4.58x | 7.2x, and 2.7x on the wire |
| 4 KiB | 1.25 ms (3.1 MB/s) | 0.179 ms (22.8 MB/s) | 7.0x |
| 256 KiB | 1.51 ms (166 MB/s) | 0.428 ms (612 MB/s) | 3.5x |
| 1 MiB | 2.31 ms (433 MB/s) | 1.156 ms (907 MB/s) | 2.0x |
| header pair, per record | 1.20 ms (0.66 seal + 0.54 open) | 0.162 ms (0.083 + 0.079) | **7.4x** |
| header share of a 256 KiB record | 79% | 38% | – |

**Why a 3.5x shorter covertext is 7.4x cheaper.** Two effects compound, and
both were re-measured at `34b6def`:

- Ranking cost grows *faster than linearly* with the covertext length. The
  per-length table above is the direct evidence: 0.158 ms at length 200 against
  1.249 ms at 700 for the same operation on the same pattern — 0.79 µs per
  covertext byte against 1.78 µs. (Those two rows also reproduce the old
  header figure exactly, which is how we know this is a length effect and not
  measurement drift between the two revisions.)
- A shorter covertext has a smaller plaintext capacity, and `_seal` pads to
  capacity for realism: 63 bytes at length 200 against 448 at 700. Encrypting
  the header's bare 16 bytes costs 0.050 ms at 200 and 0.108 ms at 700; padded
  to capacity it is 0.077 ms and 0.646 ms. The realism rule that cost 6x now
  costs 1.5x.

The change is confined to hybrid *data* records. The handshake's two records
still seal at `max_length`, because the server scans for a hello it cannot
predict the length of, and `format` mode shares no code path with the change: its
bulk cells moved a few percent (`smtp` 1 MiB 4.12 → 4.28 Mbit/s, `dns` 2.54 →
2.73), and its setup and RTT read slightly higher than in the previous
revision (`smtp` setup 2.8 → 3.8 ms, RTT 0.42 → 0.49 ms) — machine state
between runs, not the header.

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

The architecture behind the 5–7x bulk and 3x latency win over 0.3.1 remains:
the header is still 200 rather than 700 bytes and the body cipher is unchanged.
At `34b6def`, before HTTP chunk framing, the per-record fixed cost was 0.162 ms
against that catalog's ~0.17 ms, and the record layer's 256 KiB and 1 MiB rows
(612 and 907 MB/s) were within ~10% of it. The final HTTP hybrid regex has not
been measured, and the older columns used CPython 3.14.7 and a different
definitions release, so the rows are not directly comparable.
