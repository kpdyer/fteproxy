# Measurements from 2026-09-03

This archive contains the raw runs and collection scripts behind
[PERFORMANCE.md](../../PERFORMANCE.md), measured at `34b6def`.
Environment: Apple M3 Pro (12 cores, 36 GB), macOS 26.6.2, CPython 3.12.14,
fte 0.4.0, definitions `20260903`, loopback.

**HTTP hybrid timings predate the chunked-header correction.**
They used the base regex at 200 bytes followed by a raw body.
Keep these files as historical evidence; save new results elsewhere.

## End-to-end runs

From the repository root with dependencies installed:

```bash
python3 benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --baseline
python3 benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --format smtp --mode format
python3 benchmark.py --scenarios lan --sizes 64K 1M 8M --repeat 3 --format dns --mode format
```

`raw/http_hybrid_*.json`, `raw/smtp_format_*.json`, and
`raw/dns_format_*.json` each contain three whole runs.
Each throughput run retains the best repeated transfer; the report takes the
median and range across runs. The forward-port probe warms a tunnel before
measurement, but each transfer still opens a new connection.

## Collection scripts

| Script | Purpose | Archived output |
|---|---|---|
| `recordbench.py` | Record costs, per-length rates, header/body split, cache costs | `raw/rec_*.json` |
| `extra.py` | Padding cost and capacities | `raw/extra_*.json` |
| `firstconn.py` | First tunneled connection versus warmed connections | `raw/first_*.json` |
| `startup.py` | Import, definitions load, cold/warm session construction | `summary.txt` |
| `startup_e2e.py` | Process start to listening | `summary.txt` |
| `coldproc.py` | Compile two lengths in one process | `summary.txt` |
| `agg.py` | Aggregate saved raw runs | `summary.txt` |

The scripts retain historical assumptions and paths. Inspect `ROOT` and
output paths before rerunning them. In particular, `recordbench.hybrid_split`
measures the base regex, not the current separate hybrid regex, and
`coldproc.py` loads the maximum-length DFA before its timer. They are not
drop-in current-carrier benchmarks.

To inspect the existing aggregate without overwriting it:

```bash
python3 benchmarks/2026-09-03/agg.py
```

Run benchmarks separately from tests and other workloads to avoid resource
contention. Some examples use fixed ports; the main benchmark allocates
temporary ports.
