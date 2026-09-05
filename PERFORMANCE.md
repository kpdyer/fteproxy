# fteproxy performance measurements

These are historical measurements from 2026-09-03, not current performance
guarantees. Raw results and collection scripts are in
[benchmarks/2026-09-03](benchmarks/2026-09-03/README.md).

| | |
|---|---|
| commit | `34b6def` (fteproxy 1.0.0) |
| definitions | release `20260903` — `http`, `ftp`, `smtp`, `sip`, `dns` |
| measured default configuration | format `http`, mode `hybrid` (200 B base-regex header + raw body; superseded) |
| machine | Apple M3 Pro, 12 cores, 36 GB, macOS 26.6.2 (arm64) |
| interpreter | CPython 3.12.14, `fte` 0.4.0, `cryptography` 50.0.1 (OpenSSL backend) |
| date | 2026-09-03, loopback only |

The measured HTTP hybrid carrier used a 200-byte base-regex header and a raw
body. It predates the separate chunked-header grammar. Current HTTP uses a
different DFA and adds chunk framing; remeasure it before quoting current
latency or throughput.

## Run the benchmark

From a checkout with fteproxy installed:

```bash
python3 benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --baseline
python3 benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --format smtp --mode format
python3 benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --format dns --mode format
```

Run one benchmark at a time on an otherwise idle machine. Use `--json FILE`
to save new results outside the historical raw-data directory.
`--help` lists scenarios and workloads; `--help-netem` describes optional
kernel-level network shaping.

The benchmark starts real client/server subprocesses. Its userspace shaper
adds delay, jitter, bandwidth limits, or disconnects to a TCP stream; it is
not a packet-loss simulator. HTTP tests use a direct TCP path that preserves
bytes and do not measure protocol-conversation realism.

## Method and limits

Latency uses one connection after warmup; setup measures connection creation
through the first echoed byte. Throughput opens a new connection per transfer,
starts timing after the local TCP connect, and includes tunnel setup still in
progress. Its echo rate counts the payload once, although that payload travels
in both directions. Upload measures local sending, not confirmed delivery to
the destination.

Each throughput run retains its best of three successful transfers. Tables
report the median and range across three whole runs. RTT/setup figures
aggregate the per-run statistics, rather than pooling all individual samples.

The forward-port readiness probe itself opens a tunnel and warms the caches.
The separate `firstconn.py` probe waits on a timer before its first tunneled
connection. Record-layer measurements time encode plus decode without sockets.
Do not subtract an independently measured setup median from a throughput
sample to claim a measured steady-state rate.

## End-to-end loopback results

All values below describe the archived revision and environment.

| metric | plain TCP | **`http` hybrid (default)** | `smtp` format | `dns` format |
|---|---:|---:|---:|---:|
| connection setup p50 | – | **5.7 ms** (5.7–5.8) | 3.8 ms (3.6–4.3) | 4.2 ms (4.0–4.4) |
| RTT 64 B p50 | 0.13 ms (0.12–0.16) | **0.50 ms** (0.49–0.51) | 0.49 ms (0.48–0.50) | 0.66 ms (0.66–0.70) |
| RTT 64 B p90 | 0.23 ms | **0.59 ms** | 0.65 ms | 0.87 ms |
| 64 KiB echo | 452 Mbit/s (425–482) | **101 Mbit/s** (100–101) | 2.98 Mbit/s (2.86–3.00) | 1.82 Mbit/s (1.80–2.00) |
| 1 MiB echo | 2838 Mbit/s (2147–3247) | **1162 Mbit/s** (1159–1164) | 4.28 Mbit/s (4.28–4.35) | 2.73 Mbit/s (2.71–2.74) |
| 8 MiB echo | 5803 Mbit/s (5330–6088) | **3511 Mbit/s** (3425–3533) | 4.98 Mbit/s (4.95–5.08) | 3.24 Mbit/s (3.22–3.26) |

The observed SMTP/DNS format-mode rates are much lower than hybrid rates.
These LAN results do not establish that fteproxy matches raw TCP on arbitrary
WAN links or for every format.

## Record layer without sockets

HTTP hybrid at the archived revision, with a 200-byte base header and raw body:

| message | ms/record | MB/s | wire bytes | expansion |
|---|---:|---:|---:|---:|
| 64 B | 0.173 (0.172–0.173) | 0.37 | 293 | 4.58x |
| 4 KiB | 0.179 (0.178–0.180) | 22.8 | 4325 | 1.06x |
| 256 KiB (the relay's record size) | 0.428 (0.427–0.429) | 612 (610–614) | 262373 | 1.0009x |
| 1 MiB (the body cap) | 1.156 (1.127–1.172) | 907 (895–931) | 1048805 | 1.0002x |

SMTP forced into hybrid mode, for a comparison with its shorter header:

| message | ms/record | MB/s | wire bytes | expansion |
|---|---:|---:|---:|---:|
| 64 B | 0.076 (0.075–0.077) | 0.84 | 173 | 2.70x |
| 4 KiB | 0.081 (0.081–0.081) | 50.5 | 4205 | 1.03x |
| 256 KiB | 0.329 (0.328–0.330) | 797 (794–800) | 262253 | 1.0004x |
| 1 MiB | 1.053 (1.009–1.055) | 996 (994–1040) | 1048685 | 1.0001x |

That SMTP configuration appends ciphertext outside the apparent protocol.
Its normal CLI mode hint is `format`.

### Format mode at each length

Each row measures one format-mode record. A live variable-length stream mixes
these sizes according to the queued payload.

HTTP request, base grammar:

| covertext length | 200 | 271 | 343 | 414 | 486 | 557 | 629 | 700 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| payload per record (B) | 50 | 105 | 160 | 215 | 270 | 325 | 380 | 435 |
| ms per record (encode+decode) | 0.158 | 0.255 | 0.378 | 0.508 | 0.663 | 0.843 | 1.028 | 1.249 |
| MB/s | 0.32 | 0.41 | 0.42 | 0.42 | 0.41 | 0.39 | 0.37 | 0.35 |
| wire expansion | 4.00x | 2.58x | 2.14x | 1.93x | 1.80x | 1.71x | 1.66x | 1.61x |

DNS request; wire lengths include the two-byte TCP prefix:

| covertext length | 90 | 116 | 142 | 168 | 194 | 220 | 246 | 272 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| payload per record (B) | 9 | 28 | 47 | 66 | 84 | 103 | 122 | 141 |
| ms per record (encode+decode) | 0.076 | 0.101 | 0.127 | 0.158 | 0.186 | 0.217 | 0.252 | 0.290 |
| MB/s | 0.12 | 0.28 | 0.37 | 0.42 | 0.45 | 0.47 | 0.48 | 0.49 |
| wire expansion | 10.0x | 4.14x | 3.02x | 2.55x | 2.31x | 2.14x | 2.02x | 1.93x |

The measured per-byte cost depends on both the grammar and length.
The DNS rate changes by roughly fourfold across its range; length selection
can affect throughput as well as latency and wire expansion.

### Compilation and startup

Historical DFA compilation time:

| length | `http` | `dns` |
|---|---:|---:|
| shortest | 2.38 ms (at 200) | 2.85 ms (at 90) |
| middle | 5.02 ms (at 414) | 3.61 ms (at 168) |
| longest | 9.86 ms (at 700) | 5.03 ms (at 272) |
| all eight | 46.2 ms | 30.7 ms |

Definitions loading checks each base regex at its maximum length.
Session setup may compile additional allowed lengths or hybrid grammars.
The process caches ranking tables by pattern and length; bounded caches can
evict entries and require recompilation.

Historical session-channel construction after definitions loading:

| | cold | warm |
|---|---:|---:|
| `http`, hybrid (2 header DFAs at 200) | 6.0 ms | 0.024 ms |
| `smtp`, format (16 DFAs) | 21.4 ms | 0.090 ms |
| `dns`, format (16 DFAs) | 67.5 ms | 0.089 ms |
| `http`, format (16 DFAs) | 98.4 ms | 0.116 ms |
| `sip`, format (16 DFAs) | 183.1 ms | 0.110 ms |

Historical first tunneled connection versus warmed connections:

| | first connection | steady p50 |
|---|---:|---:|
| `http`, hybrid (default) | 34.7 ms (27.9–42.8) | 5.8 ms |
| `smtp`, format | 32.1 ms (30.7–48.6) | 3.1 ms |
| `dns`, format | 82.1 ms (81.2–98.4) | 3.4 ms |
| `sip`, format | 225.4 ms (224.0–227.3) | 7.6 ms |

These startup timings also predate later validation and HTTP framing changes.
The archived log records approximately 14 ms to import fteproxy, 165 ms to load
definitions, and 236 ms from process start to a listening server.

## Current wire-size calculation

For one HTTP hybrid record carrying `P` application bytes:

```text
B = P + 29
wire bytes = 200 + B + len(format(B, "x")) + 9
```

The 29 bytes are the record type, 12-byte nonce, and 16-byte tag.
The remaining suffix is one chunk-size line and a terminal zero chunk.
For example, a 64-byte payload occupies 304 wire bytes; a 256 KiB payload
occupies 262,387 bytes. These are derived sizes, not fresh timing measurements.
Control records and the two maximum-length handshake covertexts add overhead
outside that data-record calculation.

## Historical header-length change

The following comparison was recorded between `7093571` (700-byte HTTP
hybrid headers) and `34b6def` (200-byte headers), before chunked framing.

| metric | before (700 B header) | after (200 B header) | change |
|---|---:|---:|---:|
| connection setup p50 | 10.0 ms | 5.7 ms | 1.8x |
| RTT 64 B p50 | 2.52 ms | 0.50 ms | 5.0x |
| RTT 64 B p90 | 2.71 ms | 0.59 ms | 4.6x |
| 64 KiB echo | 53 Mbit/s | 101 Mbit/s | 1.9x |
| 1 MiB echo | 574 Mbit/s | 1162 Mbit/s | 2.0x |
| 8 MiB echo | 1119 Mbit/s | 3511 Mbit/s | 3.1x |

| message | before | after | change |
|---|---:|---:|---:|
| 64 B | 1.25 ms, 793 B, 12.4x | 0.173 ms, 293 B, 4.58x | 7.2x, and 2.7x on the wire |
| 4 KiB | 1.25 ms (3.1 MB/s) | 0.179 ms (22.8 MB/s) | 7.0x |
| 256 KiB | 1.51 ms (166 MB/s) | 0.428 ms (612 MB/s) | 3.5x |
| 1 MiB | 2.31 ms (433 MB/s) | 1.156 ms (907 MB/s) | 2.0x |
| header pair, per record | 1.20 ms (0.66 seal + 0.54 open) | 0.162 ms (0.083 + 0.079) | **7.4x** |
| header share of a 256 KiB record | 79% | 38% | – |

The comparison supports choosing the shortest capable hybrid header.
It does not measure the current header grammar.

### Earlier shape-catalog comparison

These older figures were recorded on 2026-09-02 with CPython 3.14.7 and
`manual-http` from `20260110`. They use a different interpreter and
definition from the tables above; the columns are historical reference only.

| metric | plain TCP | 0.3.1 (`fte` 0.3.0) | 1.0 hybrid, 256 B format | 1.0 format, 256 B |
|---|---:|---:|---:|---:|
| connection setup p50 | – | 2.7–3.3 ms | 1.1 ms | ~1 ms |
| RTT 64 B p50 | 0.15 ms | 1.5–1.7 ms | 0.51 ms | 0.73 ms |
| 1 MB echo | 2596 Mbit/s | 452–522 Mbit/s | 2540 Mbit/s | 7.3 Mbit/s |
| 8 MB echo | 6071 Mbit/s | 655–700 Mbit/s | 4626 Mbit/s | – |
| record layer, 256 KiB | – | 75–88 MB/s | 657–713 MB/s | 0.9–1.8 MB/s |
| record layer, 1 MiB | – | 75–89 MB/s | 920–960 MB/s | 1.0–1.8 MB/s |
| per-record fixed cost | – | ~0.9 ms | ~0.17 ms | – |

## Follow-up measurements

Potential work should be evaluated against a fresh baseline:

- Reassess relay polling and shutdown under latency, backpressure, and link
  interruption. Earlier experiments reported a regression when removing the
  idle throttle; that is historical evidence, not a universal scheduling rule.
- Compare lazy DFA compilation with startup prewarming.
- Measure header and body costs separately before choosing a cryptographic
  or framing change.

The archived resilience observations were not rerun for the 2026-09-03 tables.
Use `python3 benchmark.py --scenarios broadband --resilience` for a fresh
observation. A socket timeout is not an idle-session deadline: the relay polls
readiness and can leave an idle connection open.
