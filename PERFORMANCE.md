# fteproxy performance analysis

Companion to [`benchmark.py`](benchmark.py). All numbers below were produced by that
script on loopback (macOS, Python 3.14, `fte` 0.2.1), comparing fteproxy against a
**plain-TCP relay of identical two-hop topology** so the cost of Format-Transforming
Encryption is isolated from the cost of the network conditions. The "network" is an
in-process link shaper (one-way delay + jitter + bandwidth cap); see the note in
`benchmark.py` on why that faithfully models what TCP loss/reorder look like to the
application layer.

Reproduce:

```bash
pip install -e .                       # needs the `fte` dependency
python3 benchmark.py --baseline        # default 6 scenarios
python3 benchmark.py --scenarios lan broadband dsl --sizes 1M 8M --baseline --no-latency --no-setup
```

---

## TL;DR

1. **On any real-world link (≤ ~25 Mbit), fteproxy is as fast as raw TCP.** For bulk
   transfers it reaches **99%** of the plain-TCP baseline on the 5 Mbit and 25 Mbit
   links — the network is the bottleneck and FTE overhead is invisible.
2. **fteproxy's own ceiling is CPU, not the network: ~300 Mbit/s of FTE per stream.**
   This only becomes the limiter on LAN/datacenter-speed links, where fteproxy is
   ~25× slower than raw TCP.
3. **The dominating cost is a large FIXED per-call cost in FTE (~0.7 ms/encode).**
   Throughput is entirely determined by how much plaintext is packed into each cell:
   a 64-byte message runs at 0.7 Mbit/s and **expands 4×**; a 32 KB cell runs at
   ~300 Mbit/s with ~0% expansion.
4. **Interactive latency overhead is a small, roughly constant few milliseconds** (two
   encodes + two decodes per round trip) — negligible on any link with real latency,
   but 10× the raw RTT on loopback.
5. **Abrupt link drops are *usually* detected fast (~0.5 s) but not reliably.** In ~10–20%
   of trials the application connection wedges instead — a real robustness bug rooted in
   the relay's polling design (see below). fteproxy's nominal 30 s socket timeout does
   **not** rescue it, because the poll loop never lets that timeout fire.

---

## Measured data

### Bulk throughput — 8 MB echo (round trip, exercises both FTE directions)

| Link (shaper)      | fteproxy | plain-TCP | fteproxy / baseline |
|--------------------|---------:|----------:|--------------------:|
| LAN (loopback)     | 210 Mbit/s | 5553 Mbit/s | 3.8% |
| broadband (25 Mbit)| 24.5 Mbit/s | 24.8 Mbit/s | **99%** |
| dsl (5 Mbit)       | 4.94 Mbit/s | 4.98 Mbit/s | **99%** |

> On a constrained link the two lines are on top of each other; on LAN the FTE CPU
> ceiling (~300 Mbit/s single stream) is the wall.

### Interactive latency — 64 B request/response, connection reused

| Link            | fteproxy RTT | plain-TCP RTT | FTE overhead |
|-----------------|-------------:|--------------:|-------------:|
| LAN             | 1.70 ms | 0.19 ms | +1.5 ms |
| broadband       | 32.2 ms | 24.5 ms | +7.7 ms |
| dsl             | 59.9 ms | 56.0 ms | +3.9 ms |
| 3g (200 ms)     | 219.6 ms | 215.9 ms | +3.7 ms |
| edge (400 ms)   | 424.8 ms | 401.2 ms | +23 ms* |
| satellite (1200 ms) | 1215 ms | 1213 ms | +2 ms |

> \*edge has ±60 ms of injected jitter, so its overhead figure is mostly noise. The
> real signal: fteproxy adds a small **constant** delay, so its relative cost vanishes
> as link latency grows.

### Connection setup (open → first byte back), fteproxy

Tracks **~1 RTT + a few ms** (the FTE negotiation cell rides on the first data segment,
so setup is one round trip): LAN 2.8 ms, broadband 32 ms, dsl 64 ms, satellite 1221 ms.

### Raw FTE cost by cell size (the root cause)

| plaintext | ciphertext | expansion | encode | decode |
|----------:|-----------:|----------:|-------:|-------:|
| 64 B    | 256 B  | 4.0× | 0.7 Mbit/s | 1.0 Mbit/s |
| 1 KB    | 1.1 KB | 1.1× | 11.8 Mbit/s | 13.6 Mbit/s |
| 4 KB    | 4.2 KB | 1.0× | 46 Mbit/s | 54 Mbit/s |
| 16 KB   | 16.5 KB| 1.0× | 168 Mbit/s | 193 Mbit/s |
| 32 KB   | 32.9 KB| 1.0× | **299 Mbit/s** | **347 Mbit/s** |

Single-call latency is ~0.69 ms/encode and ~0.62 ms/decode regardless of size in the
small range — i.e. a **fixed per-call cost** that amortizes only when cells are large.

### Resilience — link dropped mid-transfer (bidirectional app: sends and receives)

Most of the time the app is freed within ~0.5 s of the drop (the relay worker reading the
severed side sees EOF and closes the app connection). **But intermittently — ~10–20% of
runs in this harness, across both fast and slow links — the app instead hangs past the
12 s observation window.** This is not a shaper artifact; it is a real behavior:

- A relay `worker` blocked in `sendall` to one peer never checks whether its *other* peer
  disconnected, so the drop goes unnoticed until it happens to return from that write.
- The nominal 30 s `runtime.fteproxy.relay.socket_timeout` cannot save it: the worker
  reads via `select(timeout=0.1)` + a `throttle` sleep, so a blocking `recv` never runs
  long enough to hit the socket timeout. The backstop is effectively dead code.

See improvement #2 — this is a correctness issue, not only a performance one.

---

## Where the time goes

```
app → [client relay] ──FTE──→ [server relay] → dest
        │                         │
        │ worker thread pair      │ worker thread pair
        │ poll+relay              │ negotiate + poll+relay
        └─ _FTESocketWrapper.send └─ _FTESocketWrapper.recv
             = record_layer.Encoder  = record_layer.Decoder
             = fte.Encoder.encode     = fte.Encoder.decode  ← ~0.7 ms/call, the hot spot
```

Per interactive round trip the payload is FTE-**encoded twice** (client→server request,
server→client response) and **decoded twice** — ~2.6 ms of pure CPU on top of the wire
RTT. For bulk transfer the same CPU is the throughput ceiling (~300 Mbit/s) because a
single stream's encode/decode is serialized (Python, one core).

---

## Recommended improvements, ranked by impact ÷ effort

### 1. Set `TCP_NODELAY` on relay sockets — *low effort, clear win for latency* — ✅ IMPLEMENTED

The relay used to leave Nagle's algorithm enabled. `_FTESocketWrapper` passes small encoded
cells straight to the kernel, so on a real network Nagle can hold a small segment up to
~40 ms waiting to coalesce — exactly the wrong behavior for an interactive, latency-sensitive
tunnel. `listener.run()` now disables Nagle on both hops right after `accept()`/`connect()`:

```python
# fteproxy/relay.py listener.run(), after accept()/connect():
conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
new_stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
```

Neutral on loopback (no Nagle delay to remove there, so the benchmark is unchanged), but it
removes the coalescing stall on real links.

### 2. Rework the polling relay loop — *fixes latency, idle CPU, AND a hang bug* — ⚠️ NEEDS FULL REWORK (not a quick tweak)

> **Empirical caveat (measured on this branch).** The tempting shortcut — just deleting the
> redundant-looking `time.sleep(throttle)` in `worker.run()`, since `recvall_from_socket`
> already blocks in `select` when idle — makes things **dramatically worse** in the real
> subprocess deployment: LAN throughput fell **217 → 16 Mbit/s (~13×)** and interactive RTT
> rose **1.3 → 32 ms**, reproducibly, even for the throughput path in isolation. (An
> *in-process* relay is unaffected — it is a subprocess/GIL-scheduling interaction.) The
> throttle is therefore **load-bearing** under the current `select`-based design; it must stay
> until the loop is properly reworked as below (blocking `recv` governed by the socket timeout,
> or a `selectors` event loop). **Do not simply delete the sleep.**

This is the highest-value change because it has a **correctness** payoff on top of
performance. Today `fteproxy/network_io.py:recvall_from_socket` blocks up to
`select_timeout` (0.1 s) in `select()`, and the worker *also* sleeps
`runtime.fteproxy.relay.throttle` (10 ms, `conf.py:95`) on every empty poll (`relay.py:47`).
Three problems:

- **Latency / ripple**: the extra sleep adds delay at every flow transition.
- **Idle CPU**: every idle connection's *two* threads wake on a fixed 100 ms cadence.
- **Hang on drop (correctness)**: because the loop never issues a blocking `recv` that
  lasts, the 30 s `socket_timeout` never fires — so when a peer half-closes/blackholes and
  the paired worker is stuck in `sendall`, the connection can wedge indefinitely (the
  intermittent "hung" result above).

Fix: replace the `select`+`sleep` poll with a plain blocking `recv` governed by the
socket's own timeout (so the 30 s backstop becomes real), and make the worker treat a
timeout as "tear down both sockets" so a stalled peer can't wedge the pair. A `selectors`
event loop (see #7) subsumes this.

### 3. Coalesce small writes into fewer FTE cells — *medium effort, big win for chatty traffic*

Because each FTE cell pays ~0.7 ms and (for tiny payloads) expands 4×, throughput for
chatty/interactive protocols is dominated by cell **count**, not bytes. The record layer
already buffers (`fteproxy/record_layer.py`), but `_FTESocketWrapper.send` flushes on
every `send()` call, so N small application writes become N tiny cells. A small
coalescing window on the encode side (accumulate until ~a few KB **or** ~1–2 ms elapse,
then flush) would collapse many tiny cells into one, cutting both CPU and the 4×
expansion. This is a latency/throughput trade-off, so gate it behind a config flag and a
short timer so interactive latency isn't harmed.

### 4. Fix the O(n²) buffer slicing in the record layer — *low effort, bulk CPU*

`record_layer.Encoder.pop` does `self._buffer = self._buffer[MAX_CELL_SIZE:]` and
`retval += covertext` in a loop (`fteproxy/record_layer.py:37-43`); `Decoder.pop` is
similar. Each iteration re-copies the whole remaining buffer, so a single large `push`
is quadratic in the number of cells. Measured degradation is mild today (298 → 279 Mbit/s
from 64 KB → 4 MB) because FTE dominates, but it will bite harder if FTE is ever sped up.
Use a read offset / `memoryview`, or a `bytearray` with `del buf[:n]`, and join output
chunks once.

### 5. Short-circuit the negotiation scan — *low effort, connection-setup CPU at scale* — ✅ IMPLEMENTED (ordering, not caching)

`NegotiationManager._acceptNegotiation` (`fteproxy/__init__.py`) linearly tries to decode the
first cell against **every** request-language (~23 of them) until one succeeds. The default
upstream language sits at position **21 of 23** in definition order, so every connection paid
~20 failed decodes before matching. The scan now tries the configured
`runtime.state.upstream_language` first (**~0.55 → ~0.39 ms/connection** for the common
shared-config case), falling through to the full scan for non-default clients — same set of
languages, just the expected one first.

> The originally-suggested *object caching* was measured to be a non-starter: constructing all
> 23 `fte.Encoder`s costs **0.01 ms** (the DFA tables are already cached globally by `fte`), so
> there is nothing worth caching. The only remaining lever beyond ordering is an explicit
> format id to make the common case truly O(1).

### 6. The single-stream FTE ceiling is fundamental — *large effort, only matters on fast links*

~300 Mbit/s per stream is a CPU limit: FTE ranking/unranking runs in Python and a single
connection's encode/decode is serialized by the GIL (only the AES step in pycryptodome
releases it). This is irrelevant for censorship-circumvention over real Internet paths,
but if datacenter-speed throughput is ever a goal, the levers are: parallelize
encode/decode across cores (process pool per connection, or offload the ranking to a C
extension that releases the GIL), and/or raise `record_layer.max_cell_size`
(`conf.py:103`, currently 32 KB) so fewer, larger cells are encoded.

### 7. Scalability of the thread-per-connection model — *large effort, many-connection servers*

Every proxied connection uses **two** OS threads that poll on a 100 ms cadence
(`relay.py` `worker`). This is fine for a handful of streams but caps out well before
C10k and burns CPU on idle-connection wakeups. A `selectors`-based event loop (or
`asyncio`) would scale to far more concurrent tunnels with far less overhead — but it's a
real rearchitecture of the relay core.

---

## What did *not* turn out to be a problem

- **Slow / high-latency / low-bandwidth links.** fteproxy matches raw TCP there (99% on
  bulk). The user's instinct was right: TCP absorbs loss/reorder below the app layer, and
  fteproxy's constant few-ms overhead is lost in the network's own latency.
- **DFA table build cost.** Expensive per language (~17 ms cold) but cached globally by
  `fte` and pre-built once at server startup — not a per-connection cost.
- **The record layer itself.** Its throughput (298 Mbit/s) equals raw 32 KB FTE, so it
  adds no measurable overhead on top of FTE today (see #4 for the latent quadratic).
