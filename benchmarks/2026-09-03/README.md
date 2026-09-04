# Measurements behind PERFORMANCE.md (2026-09-03)

The raw results and the scripts that produced the numbers in `PERFORMANCE.md`
for fteproxy 1.0.0 with hybrid headers sealed at the shortest capable length.
Machine: Apple M3 Pro (12 cores, 36 GB), macOS 26.6, CPython 3.12.14, fte 0.4.0,
definitions release 20260903, loopback only.

## End to end (the tables' first section)

Run from the repository root, one process at a time, never alongside the test
suite (both bind fixed ports):

```bash
uv run python benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --baseline
uv run python benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --format smtp --mode format
uv run python benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --format dns --mode format
```

`raw/http_hybrid_*.json`, `raw/smtp_format_*.json` and `raw/dns_format_*.json`
are three whole runs of each; the document reports the p50 across runs and the
range. Note that `benchmark.py` warms the server before it measures (waiting for
the client's forward port builds a tunnel), so its rows are steady state.

## Record layer, DFA compile, and cold start (the later sections)

| script | measures | output |
|---|---|---|
| `recordbench.py` | hybrid and format-mode record cost per size and per covertext length, header/body split | `raw/rec_*.json` |
| `extra.py` | seal-padding cost, cost per covertext byte, capacities per length | `raw/extra_*.json` |
| `firstconn.py` | cold first tunnelled connection versus steady state, timer-based (no warming connect) | `raw/first_*.json` |
| `startup.py`, `startup_e2e.py`, `coldproc.py` | import and definitions-load time, first session channel cold versus warm, process start to listening | in `summary.txt` |
| `agg.py` | aggregates the raw runs into the p50/range figures quoted in the document | `summary.txt` |

The scripts were run from a session scratch directory and some write their
output to that path; adjust the output path before re-running. They are kept
as run, so the numbers in `PERFORMANCE.md` can be traced to exactly what
produced them.
