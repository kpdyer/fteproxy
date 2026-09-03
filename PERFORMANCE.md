# fteproxy performance analysis

Companion to [`benchmark.py`](benchmark.py). The numbers below were produced by
that script on loopback (Apple M3 Pro, macOS, Python 3.14.7) on 2026-09-02 for
**fteproxy 1.0.0 with `fte` 0.4.0** (the tree of the 1.0 release stack), with
**fteproxy 0.3.1 + `fte` 0.3.0** measured the same day on the same machine for
comparison, and a **plain-TCP relay of identical two-hop topology** so the cost
of Format-Transforming Encryption is isolated from the network. Everything here
was measured unless marked *estimated*.

Reproduce:

```bash
pip install -e .                       # needs fte>=0.4.0,<0.5.0
python3 benchmark.py --baseline        # default 6 scenarios
python3 benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 2 --baseline
python3 benchmark.py --scenarios lan --sizes 8M --direction upload --no-latency --no-setup
python3 benchmark.py --scenarios lan --sizes 64K 1M --mode format
```

---

## TL;DR

1. **On any real-world link (≤ ~25 Mbit) fteproxy is as fast as raw TCP.** That was
   true on 0.3 and is unchanged: the network is the bottleneck and FTE is invisible.
   Everything below is about LAN/datacenter-speed links and interactive latency.
2. **The 0.4 record layer is 5–7x faster than 0.3.1 in bulk on LAN** (8 MB echo
   0.7 → 4.6 Gbit/s, ~75% of plain TCP) and **3x lower in interactive overhead**
   (64 B RTT 1.5 → 0.5 ms). The per-record fixed cost fell from ~0.9 ms to ~0.17 ms
   (round trip), and the body is OpenSSL AES-CTR+HMAC instead of a big-integer frame.
3. **The ceiling is now the relay loop and the GIL, not FTE.** The record layer alone
   runs 650–950 MB/s (5–7.5 Gbit/s) per direction; the two-thread-per-connection
   relay gets ~4.6 Gbit/s echo out of it.
4. **`format` mode (every byte in the target format) is interactive-only:** same RTT
   class as `hybrid` (0.7 vs 0.5 ms) but 4–7 Mbit/s bulk, because the DFA runs on
   every ~140 bytes instead of once per record. Its cost is inherent to the mode.
5. **libfte 0.4 caches nothing.** 0.3 cached its DFA tables globally, so building an
   encoder was free; 0.4 compiles a DFA per `RegexFormat` (0.5–1.5 ms). fteproxy
   therefore caches ciphers itself (`_make_cipher`, one per pattern/length/key),
   which brings connection setup to ~1 ms. Without the cache it was 8–12 ms, and a
   connection closed before negotiating pinned the server at 64–100% CPU.
6. **Four of the five shipped formats run in `format` mode by design, so point 4
   is their normal operating point.** Since the `20260903` definitions release the
   default catalog is five cleartext protocols: `http` is `mode_hint: hybrid` (an
   HTTP message with a raw body is what HTTP looks like), while the line protocols
   `ftp`, `smtp`, `sip` and the binary `dns` format are `mode_hint: format`,
   because a line protocol has no place to put a high-entropy tail. Expect about
   1 MB/s and interactive-class latency on those four — fine for a shell, a chat,
   or SOCKS-proxied browsing of text, and not a bulk-transfer channel. Pick `http`
   (or pass `--mode hybrid`, accepting the tail) when throughput is what matters.
   The measurements below predate the release and were taken on
   `manual-http-request`/`-response` from the shape catalog; the `hybrid` column
   is representative of `http`, and the `format` column of the other four.
7. **The relay's `select`+throttle poll loop is unchanged** and still carries the
   caveats from 0.3: do not delete the throttle, and a dropped link can still wedge
   an application connection (see *Resilience*).

---

## Measured data (LAN, loopback)

| metric | plain TCP | 0.3.1 | **0.4 hybrid (default)** | 0.4 format |
|---|---:|---:|---:|---:|
| connection setup p50 | – | 2.7–3.3 ms | **1.1 ms** | ~1 ms |
| RTT 64 B p50 (p90) | 0.15 (0.28) ms | 1.5–1.7 ms | **0.51 (0.55) ms** | 0.73 (0.92) ms |
| 64 KB echo | 413–1225 Mbit/s | 113–144 Mbit/s | **557 Mbit/s** | 4.4 Mbit/s |
| 1 MB echo | 2596 Mbit/s | 452–522 Mbit/s | **2540 Mbit/s** | 7.3 Mbit/s |
| 8 MB echo | 6071 Mbit/s | 655–700 Mbit/s | **4626 Mbit/s** | – |
| 8 MB upload (one direction) | – | 1069–1275 Mbit/s | **4412 Mbit/s** | – |

Ranges are run-to-run spread across two runs; the 64 KB transfer window
includes connection setup and the handshake, so it is the noisiest row (the
plain-TCP 64 KB figure varied 3x between runs). On the shaped links
(broadband 25 Mbit and slower) fteproxy matches plain TCP within measurement
noise, as it did on 0.3; those rows are omitted.

### Record layer alone (no sockets), `manual-http-request`/`-response`

Median encrypt+decrypt round trip through `fteproxy.record_layer`, from the
release review (same machine). `manual-http-*` is the shape catalog's HTTP
entry (release `20260110`, length 256); the shipped `http` format is length 512
with more capacity per record, which moves the small-message rows a little and
leaves the bulk rows where they are:

| message | 0.3.1 | 0.4 hybrid | 0.4 format | wire expansion 0.3.1 → 0.4 hybrid / format |
|---|---:|---:|---:|---:|
| 64 B | 0.07–0.21 MB/s (0.9 ms/record) | 0.38–0.53 MB/s (0.17 ms) | 0.40–0.65 MB/s | 4.0x → 5.4x / 4.0x |
| 4 KiB | 4.5–11.7 MB/s | 23–33 MB/s | 0.9–1.9 MB/s | 1.03x → 1.07x / 1.81x |
| 256 KiB | 75–88 MB/s | 657–713 MB/s | 0.9–1.8 MB/s | 1.001x → 1.001x / 1.75x |
| 1 MiB | 75–89 MB/s | 920–960 MB/s | 1.0–1.8 MB/s | 1.000x → 1.000x / 1.75x |

(Request/response formats differ in capacity, hence the pairs.)

---

## Where the time goes (0.4, `hybrid`)

```
app → [client relay] ──FTE──→ [server relay] → dest
        worker thread pair         worker thread pair
        _FTESocketWrapper.send     _FTESocketWrapper.recv
        = record_layer.Encoder     = record_layer.Decoder
          per record:                per record:
          1 sealed header            1 header rank+verify   ~0.07–0.08 ms
            (DFA unrank, AE)         + body HMAC-SHA256 verify + AES-CTR
          + body AES-CTR + HMAC        ~0.43 ms/MiB (HMAC is ~78% of it)
```

- A record is one 256-byte formatted header plus a raw body. The relay hands
  at most `2**18` bytes to `send()` per read (`network_io.recvall_from_socket`),
  so records are ≤ 256 KiB and each pays one header (~0.08 ms ≈ 0.33 ms/MiB,
  *estimated* ~40% of encode-side record-layer time). The 1 MiB body cap is
  never reached in the relay.
- Sealing (random pad to capacity), per-record `Cipher` construction, buffer
  concatenation and the body/remainder slices are each under 1% of a record.
- Interactive traffic: one 64 B message costs one 256-byte header plus a
  92-byte body (348 B, 5.4x; 0.3 and `format` mode send 256 B).
- In `format` mode every ~140 bytes of payload is one DFA rank/unrank
  (~0.16 ms), which is the 4–7 Mbit/s.

---

## Improvements landed in 0.4

1. **Hybrid record layer with an OpenSSL AE body** (the redesign): per-record cost
   0.9 → 0.17 ms; bulk 75 → 650–950 MB/s in the record layer.
2. **Cipher cache**: the expensive half of a libfte cipher is the DFA, and
   `_regex_format` memoizes it on pattern and length, so setup went 8–12 ms →
   ~1 ms and the server's first-record scan on a failed connection 6 ms → free.
   The keyed `fte.FTE` on top is built per session (a couple of microseconds),
   because since 0.4 every connection derives its own keys.
3. **A pending header is decrypted once.** A 256 KiB record arrives in ~3 reads;
   the decoder used to re-rank and re-verify the same header on each partial
   delivery (two wasted header decrypts per record, more than the body itself).
   +30% on 8 MB echo.
4. **A peer that closes before handshaking gets EOF** instead of being polled
   forever. On 0.4 without this, one dead connection (a port scan, a health
   check, an active probe) cost 64% of a core; five saturated it and pushed
   RTT p50 to 65 ms.
5. **The handshake moved off the relay workers.** A per-connection setup thread
   completes it, reads the client's OPEN and dials the destination before
   either worker starts, so the accept loop no longer waits on a `connect()`
   and the two workers never touch a half-built encoder. That was the
   precondition for reworking the poll loop (lever #1 below).
6. Carried over from 0.3: `TCP_NODELAY` on both relay hops, O(n) buffer handling
   in the record layer, and trying the most-recently-matched format first in
   the server's first-record scan.

The handshake and the in-band destination add about 1.6 ms to connection
setup, measured on one machine against the same build without them
(0.7 -> 2.3 ms p50 on loopback): two X25519 key generations, four exchanges,
and two extra round trips (the server hello, then OPEN/OPEN_RESULT). Bulk
throughput is unchanged -- the record layer microbenchmark reads 673 MB/s at
256 KiB and 973 MB/s at 1 MiB either way.

## Remaining levers, ranked by impact ÷ effort

1. **Rework the polling relay loop** (large effort; fixes idle CPU, a latency
   ripple, and the hang on link drop). The 0.3 caveat stands and was re-verified:
   simply deleting `time.sleep(throttle)` in `worker.run()` regresses the real
   subprocess deployment ~13x (a GIL-scheduling convoy between the two workers),
   and on 0.3 a naive blocking-`recv` rework raced the in-band negotiation
   between the two workers. 0.4 removes that second obstacle — the handshake
   now finishes on a setup thread before either worker starts — so what is
   left is the GIL convoy, and the shape to try is one `selectors` loop per
   connection handling both directions. Still not a drive-by.
2. **Carry small messages inline in the sealed header** (medium effort). A message
   of ≤ ~140 bytes fits in the header's capacity, so it could travel as one
   256-byte covertext instead of header + 92-byte body: 5.4x → 4.0x expansion
   for interactive traffic, at the CPU cost `format` mode already pays per
   record (identical for one record).
3. **AES-GCM for the body** would roughly halve body CPU (*estimated*; HMAC-SHA256
   runs at ~3 GB/s vs 16 GB/s for AES-CTR), but the body is now under 10% of
   end-to-end time and it would be a wire change. Not worth it today.
4. **`format` mode throughput is inherent** to transforming every byte; the only
   lever is a faster ranker (a C extension releasing the GIL).

---

## Resilience — link dropped mid-transfer

Unchanged from 0.3, and still real: when a bidirectional application's link is
cut, the relay usually frees the app within ~0.5 s, but in a minority of runs a
worker blocked in `sendall` to one peer never checks its other peer and the
connection wedges past the observation window. The nominal 30 s
`runtime.fteproxy.relay.socket_timeout` cannot rescue it because the poll loop
never issues a blocking `recv` that lasts long enough. Lever #1 above is the fix.

What is new in 0.4 is that the *other* stuck states are fixed: a connection
closed before the handshake, and one that opens and then falls silent, both
release their worker — the first at EOF, the second at the handshake deadline.

---

## What did *not* turn out to be a problem

- **Slow, high-latency or low-bandwidth links.** fteproxy matches raw TCP there.
- **Server startup.** Building ciphers for all 46 formats takes ~23 ms cold.
- **Random padding.** `os.urandom` for the seal pad is ~1 µs of an ~80 µs header.
- **The 1 MiB body cap.** Never reached; records are bounded by the relay's read size.
- **Cell/buffer size tuning.** As on 0.3, `network_io`'s `2**18` read size is the
  right balance; larger buffers trade small-transfer latency for little bulk gain.
