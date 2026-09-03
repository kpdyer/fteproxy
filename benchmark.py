#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
benchmark.py - Performance & resilience benchmark for the fteproxy relay system.

fteproxy tunnels a plaintext TCP stream through a Format-Transforming-Encryption
(FTE) encoded channel:

    [app] --plain--> [fteproxy client] ==FTE==> [fteproxy server] --plain--> [dest]

This script spins up a real client+server pair (as subprocesses, exactly the way
users run them), drives traffic through it, and measures:

  * throughput   - bulk transfer rate for a range of payload sizes / directions
  * latency      - small request/response round-trip time (interactive traffic)
  * setup        - time to establish a new tunneled connection (FTE negotiation)
  * resilience   - behaviour when the encoded link is torn down mid-transfer

Every scenario can be run through an in-process "link shaper" that emulates a
slow / high-latency / bandwidth-constrained link, and against a plain-TCP relay
of identical topology so the *overhead of FTE itself* can be separated from the
overhead of the network conditions.

    A note on modelling unreliable networks
    ----------------------------------------
    fteproxy runs over TCP. Packet loss, reordering and duplication happen below
    TCP and are *repaired* by TCP before fteproxy ever sees the bytes. What loss
    and jitter actually look like to fteproxy is: extra latency (retransmits,
    head-of-line blocking) and reduced goodput. The shaper therefore models the
    network as {one-way delay, jitter, bandwidth cap} -- the effects that survive
    to the application layer -- plus optional mid-stream disconnects for the
    resilience tests. It deliberately does NOT drop or reorder bytes on the
    established stream (that would corrupt it, which is not what a real network
    does to a TCP flow). For true kernel-level loss/reorder see the note printed
    by `--help-netem` (needs root + dnctl/dummynet on macOS, tc/netem on Linux).

Stdlib only. Requires `fteproxy` (and its `fte` dependency) to be importable by
the same interpreter that runs this script:  python3 benchmark.py
"""

import argparse
import contextlib
import functools
import json
import os
import random
import socket
import statistics
import subprocess
import sys
import threading
import time

# progress should stream even when stdout is a pipe (e.g. redirected to a file)
print = functools.partial(print, flush=True)  # noqa: A001


# --------------------------------------------------------------------------- #
# Small networking helpers
# --------------------------------------------------------------------------- #

def free_port():
    """Ask the OS for an unused loopback TCP port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_listening(port, host='127.0.0.1', timeout=30.0):
    """Block until *something* accepts a connection on host:port.

    Note: the fteproxy relay eagerly opens a downstream connection for every
    inbound TCP connection, including this probe. All destinations in this file
    accept in a loop and discard idle/probe connections, so a probe never
    starves a real connection.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = socket.create_connection((host, port), timeout=1.0)
            c.close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def recv_n(sock, n):
    """Receive exactly n bytes (or until EOF). Returns bytes received."""
    chunks = []
    got = 0
    while got < n:
        b = sock.recv(min(1 << 16, n - got))
        if not b:
            break
        chunks.append(b)
        got += len(b)
    return b''.join(chunks)


# --------------------------------------------------------------------------- #
# Destinations (the "origin server" the proxy forwards to)
# --------------------------------------------------------------------------- #

class LoopServer(threading.Thread):
    """Threaded TCP server that accepts many connections concurrently.

    mode='echo' : echo every byte back (measures a full client->dest->client
                  round trip, exercising FTE encode AND decode in both relays).
    mode='sink' : read and discard; after EOF (or `respond` bytes requested via
                  the first 8 bytes) optionally stream back `respond` bytes.
    """

    def __init__(self, port, mode='echo'):
        super().__init__(daemon=True)
        self.port = port
        self.mode = mode
        self._running = True
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(('127.0.0.1', port))
        self.srv.listen(128)
        self.srv.settimeout(0.2)

    def run(self):
        while self._running:
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        conn.settimeout(60)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            if self.mode == 'echo':
                while True:
                    d = conn.recv(1 << 16)
                    if not d:
                        break
                    conn.sendall(d)
            elif self.mode == 'sink':
                while True:
                    d = conn.recv(1 << 16)
                    if not d:
                        break
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def stop(self):
        self._running = False
        with contextlib.suppress(OSError):
            self.srv.close()


# --------------------------------------------------------------------------- #
# Link shaper: userspace emulation of a slow / high-latency / narrow link
# --------------------------------------------------------------------------- #

class Shaper(threading.Thread):
    """A TCP relay that emulates link characteristics on the bytes passing
    through it. Sits between the fteproxy client and server:

        [fte client] --> [Shaper] --> [fte server]

    Parameters
    ----------
    delay_ms   : one-way propagation delay applied in each direction
    jitter_ms  : uniform +/- jitter added to each release
    rate_bps   : bandwidth cap in *bits* per second (0 = unlimited)
    mtu        : bytes are metered in units of this size (smoothness of the cap)
    """

    def __init__(self, listen_port, target_port,
                 delay_ms=0.0, jitter_ms=0.0, rate_bps=0, mtu=1500):
        super().__init__(daemon=True)
        self.listen_port = listen_port
        self.target_port = target_port
        self.delay = delay_ms / 1000.0
        self.jitter = jitter_ms / 1000.0
        self.rate_bps = rate_bps
        self.mtu = max(1, mtu)
        self._running = True
        self._conns = []          # active sockets, so stop() can drop the "link"
        self._conns_lock = threading.Lock()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(('127.0.0.1', listen_port))
        self.srv.listen(128)
        self.srv.settimeout(0.2)

    def run(self):
        while self._running:
            try:
                downstream, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                upstream = socket.create_connection(('127.0.0.1', self.target_port))
            except OSError:
                downstream.close()
                continue
            with self._conns_lock:
                self._conns += [downstream, upstream]
            for a, b in ((downstream, upstream), (upstream, downstream)):
                threading.Thread(target=self._pump, args=(a, b), daemon=True).start()

    def _release_delay(self):
        d = self.delay
        if self.jitter:
            d += random.uniform(-self.jitter, self.jitter)
        return max(0.0, d)

    def _pump(self, src, dst):
        """Copy src->dst applying propagation delay + a bandwidth cap.

        A single thread that both meters bandwidth AND sleeps for propagation
        delay would stop draining `src` while it sleeps, collapsing the in-flight
        window into stop-and-wait and starving throughput far below the cap. So
        the two concerns are split:

          reader  : drains `src` as fast as it arrives and stamps each MTU unit
                    with a scheduled arrival time = wire-serialisation (the
                    bandwidth cap, modelled as a virtual wire that can carry one
                    bit at a time) + propagation delay (+jitter).
          writer  : releases units to `dst` at their scheduled arrival time.

        Units in the queue are the link's bytes "in flight", so bandwidth*delay
        worth of data can be outstanding at once -- as on a real link.
        """
        import queue as _queue
        q = _queue.Queue(maxsize=4096)
        SENTINEL = None

        def reader():
            with contextlib.suppress(OSError):
                src.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                src.settimeout(60)
            wire_free_at = time.perf_counter()
            try:
                while self._running:
                    data = src.recv(1 << 16)
                    if not data:
                        break
                    for i in range(0, len(data), self.mtu):
                        unit = data[i:i + self.mtu]
                        now = time.perf_counter()
                        if self.rate_bps > 0:
                            tx = (len(unit) * 8) / self.rate_bps
                            depart = max(now, wire_free_at)
                            wire_free_at = depart + tx
                            arrive = wire_free_at + self._release_delay()
                        else:
                            arrive = now + self._release_delay()
                        q.put((arrive, unit))
            except OSError:
                pass
            finally:
                q.put(SENTINEL)

        def writer():
            with contextlib.suppress(OSError):
                dst.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                while self._running:
                    try:
                        item = q.get(timeout=0.2)
                    except _queue.Empty:
                        continue
                    if item is SENTINEL:
                        break
                    arrive, unit = item
                    # sleep in slices so a mid-flight stop() (link drop) aborts
                    # promptly and DISCARDS queued bytes, as a real link would --
                    # rather than draining the backlog over the link's rate.
                    while self._running:
                        remaining = arrive - time.perf_counter()
                        if remaining <= 0:
                            break
                        time.sleep(min(remaining, 0.1))
                    if not self._running:
                        break
                    dst.sendall(unit)
            except OSError:
                pass
            finally:
                with contextlib.suppress(OSError):
                    dst.shutdown(socket.SHUT_WR)
                with contextlib.suppress(OSError):
                    src.close()

        rt = threading.Thread(target=reader, daemon=True)
        wt = threading.Thread(target=writer, daemon=True)
        rt.start()
        wt.start()
        rt.join()
        wt.join()

    def stop(self):
        """Stop accepting AND drop any established connections, so that stopping
        the shaper faithfully emulates the link going away mid-transfer.

        We only shutdown() the active sockets here (not close()): shutdown is
        safe to call from this thread while the pump threads may be blocked in
        recv/send on the same fd -- it unblocks them with a clean EOF, which
        propagates to fteproxy as a normal close. The pump threads own the
        close(). (close() from two threads races and can send a RST instead.)"""
        self._running = False
        with contextlib.suppress(OSError):
            self.srv.close()
        with self._conns_lock:
            conns, self._conns = self._conns, []
        for s in conns:
            with contextlib.suppress(OSError):
                s.shutdown(socket.SHUT_RDWR)


# --------------------------------------------------------------------------- #
# Plain-TCP relay (baseline of identical topology, no FTE)
# --------------------------------------------------------------------------- #

class TcpRelay(threading.Thread):
    """A no-op forwarding relay: [in] --> [out]. Two of these chained give the
    same two-hop topology as fteproxy client+server, but without FTE, so the
    cost of FTE can be isolated from the cost of the extra hops + shaper."""

    def __init__(self, listen_port, target_port):
        super().__init__(daemon=True)
        self.listen_port = listen_port
        self.target_port = target_port
        self._running = True
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(('127.0.0.1', listen_port))
        self.srv.listen(128)
        self.srv.settimeout(0.2)

    def run(self):
        while self._running:
            try:
                inbound, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                outbound = socket.create_connection(('127.0.0.1', self.target_port))
            except OSError:
                inbound.close()
                continue
            for a, b in ((inbound, outbound), (outbound, inbound)):
                threading.Thread(target=self._pump, args=(a, b), daemon=True).start()

    @staticmethod
    def _pump(src, dst):
        with contextlib.suppress(OSError):
            src.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            src.settimeout(60)
        try:
            while True:
                d = src.recv(1 << 16)
                if not d:
                    break
                dst.sendall(d)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                dst.shutdown(socket.SHUT_WR)
            with contextlib.suppress(OSError):
                src.close()

    def stop(self):
        self._running = False
        with contextlib.suppress(OSError):
            self.srv.close()


# --------------------------------------------------------------------------- #
# The system-under-test: an fteproxy client+server pair (real subprocesses)
# --------------------------------------------------------------------------- #

class FteProxyTunnel:
    """Starts a real fteproxy server and client as subprocesses.

    Topology (entry_port is where the application connects):

        app -> client(entry_port) ==FTE==> [middle] ==> server -> dest(dest_port)

    where [middle] is either the server's own port, or a Shaper in front of it.
    """

    def __init__(self, dest_port, upstream_format=None, downstream_format=None,
                 record_layer_mode=None,
                 shaper_kwargs=None, verbose=False):
        self.dest_port = dest_port
        self.entry_port = free_port()
        self.server_port = free_port()
        self.upstream_format = upstream_format
        self.downstream_format = downstream_format
        self.record_layer_mode = record_layer_mode
        self.verbose = verbose
        self.procs = []
        self.shaper = None
        self._shaper_kwargs = shaper_kwargs

    def start(self):
        py = sys.executable
        out = None if self.verbose else subprocess.DEVNULL

        server_cmd = [py, '-m', 'fteproxy', '--mode', 'server', '--quiet',
                      '--server_ip', '127.0.0.1', '--server_port', str(self.server_port),
                      '--proxy_ip', '127.0.0.1', '--proxy_port', str(self.dest_port)]
        if self.record_layer_mode:
            server_cmd += ['--record-layer-mode', self.record_layer_mode]
        self.procs.append(subprocess.Popen(server_cmd, stdout=out, stderr=out))

        # Client connects either straight to the server, or via the shaper.
        if self._shaper_kwargs is not None:
            shaper_port = free_port()
            self.shaper = Shaper(shaper_port, self.server_port, **self._shaper_kwargs)
            self.shaper.start()
            client_target = shaper_port
        else:
            client_target = self.server_port

        # The destination travels in band since 0.4, so the client is the end
        # that names it.
        client_cmd = [py, '-m', 'fteproxy', '--mode', 'client', '--quiet',
                      '--client_ip', '127.0.0.1', '--client_port', str(self.entry_port),
                      '--server_ip', '127.0.0.1', '--server_port', str(client_target),
                      '--proxy_ip', '127.0.0.1', '--proxy_port', str(self.dest_port)]
        if self.upstream_format:
            client_cmd += ['--upstream-format', self.upstream_format]
        if self.downstream_format:
            client_cmd += ['--downstream-format', self.downstream_format]
        if self.record_layer_mode:
            client_cmd += ['--record-layer-mode', self.record_layer_mode]
        self.procs.append(subprocess.Popen(client_cmd, stdout=out, stderr=out))

        if not wait_listening(self.server_port):
            raise RuntimeError("fteproxy server did not come up")
        if not wait_listening(self.entry_port):
            raise RuntimeError("fteproxy client did not come up")
        # small settle so the first real connection isn't racing startup
        time.sleep(0.3)
        return self

    def stop(self):
        if self.shaper:
            self.shaper.stop()
        for p in self.procs:
            with contextlib.suppress(Exception):
                p.terminate()
        for p in self.procs:
            with contextlib.suppress(Exception):
                p.wait(timeout=5)


class PlainTunnel:
    """Identical-topology baseline built from two TcpRelays instead of fteproxy,
    with the same optional shaper in the middle."""

    def __init__(self, dest_port, shaper_kwargs=None, **_ignored):
        self.dest_port = dest_port
        self.entry_port = free_port()
        self.server_port = free_port()
        self._shaper_kwargs = shaper_kwargs
        self.relays = []
        self.shaper = None

    def start(self):
        # server-side relay: middle -> dest
        server_relay = TcpRelay(self.server_port, self.dest_port)
        server_relay.start()
        self.relays.append(server_relay)

        if self._shaper_kwargs is not None:
            shaper_port = free_port()
            self.shaper = Shaper(shaper_port, self.server_port, **self._shaper_kwargs)
            self.shaper.start()
            client_target = shaper_port
        else:
            client_target = self.server_port

        client_relay = TcpRelay(self.entry_port, client_target)
        client_relay.start()
        self.relays.append(client_relay)

        if not wait_listening(self.server_port):
            raise RuntimeError("baseline server relay did not come up")
        if not wait_listening(self.entry_port):
            raise RuntimeError("baseline client relay did not come up")
        time.sleep(0.1)
        return self

    def stop(self):
        if self.shaper:
            self.shaper.stop()
        for r in self.relays:
            r.stop()


# --------------------------------------------------------------------------- #
# Workloads
# --------------------------------------------------------------------------- #

def workload_throughput(entry_port, nbytes, direction='echo', send_chunk=1 << 16):
    """Push nbytes through the tunnel and time it.

    direction='echo'   : bytes are echoed by the destination -> full round trip
                         (both FTE directions). Rate reported is goodput of the
                         payload (sent == received == nbytes).
    direction='upload' : destination is a sink; measure how fast we can push
                         nbytes in. (Uses a sink destination -- see runner.)
    """
    payload = os.urandom(nbytes) if nbytes <= (4 << 20) else (b'x' * nbytes)
    app = socket.create_connection(('127.0.0.1', entry_port), timeout=30)
    app.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    app.settimeout(60)

    received = {'n': 0}

    def receiver():
        received['n'] = len(recv_n(app, nbytes))

    t0 = time.perf_counter()
    if direction == 'echo':
        rx = threading.Thread(target=receiver, daemon=True)
        rx.start()

    sent = 0
    mv = memoryview(payload)
    while sent < nbytes:
        n = app.send(mv[sent:sent + send_chunk])
        sent += n

    if direction == 'echo':
        rx.join(timeout=60)
        ok = received['n'] == nbytes
    else:  # upload / sink
        with contextlib.suppress(OSError):
            app.shutdown(socket.SHUT_WR)
        ok = True
    dt = time.perf_counter() - t0
    app.close()
    mbps = (nbytes * 8 / 1e6) / dt if dt > 0 else 0.0
    return {'ok': ok, 'bytes': nbytes, 'seconds': dt, 'mbit_s': mbps}


def workload_latency(entry_port, count=50, msg_size=64, warmup=5):
    """Reuse ONE connection; ping-pong a small message `count` times and record
    per-round-trip latency. Isolates steady-state interactive latency (excludes
    connection setup)."""
    app = socket.create_connection(('127.0.0.1', entry_port), timeout=30)
    app.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    app.settimeout(30)
    msg = b'p' * msg_size
    samples = []
    try:
        for i in range(count + warmup):
            t0 = time.perf_counter()
            app.sendall(msg)
            back = recv_n(app, msg_size)
            dt = (time.perf_counter() - t0) * 1000.0
            if len(back) != msg_size:
                break
            if i >= warmup:
                samples.append(dt)
    finally:
        app.close()
    if not samples:
        return {'ok': False, 'samples': 0}
    samples.sort()
    return {
        'ok': True,
        'samples': len(samples),
        'min_ms': samples[0],
        'p50_ms': statistics.median(samples),
        'p90_ms': samples[int(len(samples) * 0.9) - 1] if len(samples) >= 10 else samples[-1],
        'max_ms': samples[-1],
        'mean_ms': statistics.fmean(samples),
    }


def workload_setup(entry_port, dest_port, count=20):
    """Measure per-connection setup cost: time from opening a new tunnel
    connection until the first echoed byte comes back. This captures the FTE
    in-band negotiation the server performs on every new connection."""
    samples = []
    for _ in range(count):
        t0 = time.perf_counter()
        try:
            app = socket.create_connection(('127.0.0.1', entry_port), timeout=30)
            app.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            app.settimeout(30)
            app.sendall(b'!')
            back = recv_n(app, 1)
            dt = (time.perf_counter() - t0) * 1000.0
            app.close()
            if len(back) == 1:
                samples.append(dt)
        except OSError:
            pass
    if not samples:
        return {'ok': False, 'samples': 0}
    samples.sort()
    return {
        'ok': True,
        'samples': len(samples),
        'min_ms': samples[0],
        'p50_ms': statistics.median(samples),
        'max_ms': samples[-1],
        'mean_ms': statistics.fmean(samples),
    }


def workload_resilience(entry_port, tunnel, drop_after=0.5, observe_s=12.0):
    """Start a bidirectional transfer, tear the encoded link down mid-flight, and
    see how quickly the application side finds out. Only meaningful when the
    tunnel has a shaper we can stop (which drops the link, discarding in-flight
    bytes -- as a real link failure would).

    A real client reads and writes concurrently, so we do too: one thread streams
    the payload up, another drains the echo. We classify by how the app is freed:

      prompt : the receive side saw EOF / reset in < `observe_s`  (good)
      hung   : still blocked at the end of the observation window (bad -- see
               PERFORMANCE.md: the relay's select+throttle poll never lets the
               30 s socket timeout fire, so a stalled/half-open peer can wedge)
    """
    if not getattr(tunnel, 'shaper', None):
        return {'ok': None, 'note': 'no shaper/link to interrupt'}
    app = socket.create_connection(('127.0.0.1', entry_port), timeout=30)
    app.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    app.settimeout(observe_s)
    payload = b'x' * (8 << 20)
    state = {'freed': False}

    def killer():
        time.sleep(drop_after)
        tunnel.shaper.stop()

    def sender():
        with contextlib.suppress(OSError):
            app.sendall(payload)

    threading.Thread(target=killer, daemon=True).start()
    threading.Thread(target=sender, daemon=True).start()

    t0 = time.perf_counter()
    try:
        while True:
            d = app.recv(1 << 16)
            if not d:              # EOF: link drop propagated to us
                state['freed'] = True
                break
    except socket.timeout:
        state['freed'] = False
    except OSError:
        state['freed'] = True
    dt = (time.perf_counter() - t0) * 1000.0
    with contextlib.suppress(OSError):
        app.close()
    mechanism = 'prompt' if state['freed'] else 'hung'
    return {'ok': True, 'freed': state['freed'], 'mechanism': mechanism, 'detect_ms': dt}


# --------------------------------------------------------------------------- #
# Scenarios (named network conditions)
# --------------------------------------------------------------------------- #
# rate_bps is bits/sec. delay_ms is one-way; RTT is ~2x delay through the link.

SCENARIOS = {
    'lan':        dict(desc='ideal loopback (no shaper)',          shaper=None),
    'shaped-lan': dict(desc='shaper passthrough, ~0 delay',        shaper=dict(delay_ms=0.2,  jitter_ms=0.0, rate_bps=0)),
    'broadband':  dict(desc='25 Mbit, 20 ms RTT',                  shaper=dict(delay_ms=10,   jitter_ms=1,   rate_bps=25_000_000)),
    'dsl':        dict(desc='5 Mbit, 50 ms RTT',                   shaper=dict(delay_ms=25,   jitter_ms=3,   rate_bps=5_000_000)),
    '3g':         dict(desc='1 Mbit, 200 ms RTT, jittery',         shaper=dict(delay_ms=100,  jitter_ms=25,  rate_bps=1_000_000)),
    'edge':       dict(desc='256 kbit, 400 ms RTT, very jittery',  shaper=dict(delay_ms=200,  jitter_ms=60,  rate_bps=256_000)),
    'satellite':  dict(desc='2 Mbit, 1200 ms RTT',                 shaper=dict(delay_ms=600,  jitter_ms=20,  rate_bps=2_000_000)),
    'lossy-3g':   dict(desc='1 Mbit, 250 ms RTT, heavy jitter',    shaper=dict(delay_ms=125,  jitter_ms=90,  rate_bps=1_000_000)),
}

DEFAULT_SCENARIOS = ['lan', 'broadband', 'dsl', '3g', 'edge', 'satellite']
DEFAULT_SIZES = [64, 64 * 1024, 1024 * 1024]


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

def fmt_size(n):
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n // 1024}KB"
    return f"{n // (1024 * 1024)}MB"


def run_matrix(args):
    random.seed(1234)
    results = []
    scenarios = args.scenarios
    sizes = args.sizes

    tunnel_types = [('fteproxy', FteProxyTunnel)]
    if args.baseline:
        tunnel_types.append(('plain-tcp', PlainTunnel))

    print("=" * 78)
    print("fteproxy benchmark")
    print(f"  python      : {sys.version.split()[0]}  ({sys.executable})")
    try:
        import fteproxy as _fp
        print(f"  fteproxy    : {_fp.__version__}")
    except Exception:
        print("  fteproxy    : (import failed)")
    print(f"  scenarios   : {', '.join(scenarios)}")
    print(f"  sizes       : {', '.join(fmt_size(s) for s in sizes)}")
    print(f"  direction   : {args.direction}")
    print("=" * 78)

    for scen_name in scenarios:
        scen = SCENARIOS[scen_name]
        print(f"\n### scenario: {scen_name}  --  {scen['desc']}")
        for tun_label, TunnelCls in tunnel_types:
            dest_mode = 'echo' if args.direction == 'echo' else 'sink'
            dest = LoopServer(free_port(), mode=dest_mode)
            dest.start()
            shaper_kwargs = scen['shaper']
            try:
                tunnel = TunnelCls(dest.port, shaper_kwargs=shaper_kwargs,
                                   upstream_format=args.upstream_format,
                                   downstream_format=args.downstream_format,
                                   record_layer_mode=args.record_layer_mode,
                                   verbose=args.verbose)
            except TypeError:
                tunnel = TunnelCls(dest.port, shaper_kwargs=shaper_kwargs)
            try:
                tunnel.start()
            except Exception as e:
                print(f"  [{tun_label}] FAILED to start: {e}")
                dest.stop()
                continue

            try:
                # ----- setup / negotiation cost -----
                if args.setup and tun_label == 'fteproxy':
                    su = workload_setup(tunnel.entry_port, dest.port, count=args.setup_count)
                    if su['ok']:
                        print(f"  [{tun_label}] connection setup  : "
                              f"p50 {su['p50_ms']:.1f} ms  mean {su['mean_ms']:.1f} ms  "
                              f"min {su['min_ms']:.1f}  max {su['max_ms']:.1f}  (n={su['samples']})")
                        results.append(dict(scenario=scen_name, tunnel=tun_label,
                                            metric='setup', **su))

                # ----- latency (interactive) -----
                if args.latency:
                    lat = workload_latency(tunnel.entry_port, count=args.latency_count,
                                           msg_size=args.latency_size)
                    if lat['ok']:
                        print(f"  [{tun_label}] rtt {args.latency_size}B ping : "
                              f"p50 {lat['p50_ms']:.2f} ms  p90 {lat['p90_ms']:.2f}  "
                              f"mean {lat['mean_ms']:.2f}  min {lat['min_ms']:.2f}  "
                              f"max {lat['max_ms']:.2f}  (n={lat['samples']})")
                        results.append(dict(scenario=scen_name, tunnel=tun_label,
                                            metric='latency', **lat))
                    else:
                        print(f"  [{tun_label}] rtt ping : FAILED")

                # ----- throughput per size -----
                for size in sizes:
                    best = None
                    for _ in range(args.repeat):
                        r = workload_throughput(tunnel.entry_port, size,
                                                direction=args.direction)
                        if not r['ok']:
                            best = r
                            break
                        if best is None or r['mbit_s'] > best['mbit_s']:
                            best = r
                    tag = 'OK' if best['ok'] else 'FAIL'
                    print(f"  [{tun_label}] xfer {fmt_size(size):>5} {args.direction:6}: "
                          f"{best['mbit_s']:8.2f} Mbit/s  ({best['seconds']*1000:8.1f} ms)  {tag}")
                    results.append(dict(scenario=scen_name, tunnel=tun_label,
                                        metric='throughput', size=size,
                                        direction=args.direction, **best))

                # ----- resilience (only if a link exists to break) -----
                if args.resilience and tun_label == 'fteproxy' and shaper_kwargs is not None:
                    res = workload_resilience(tunnel.entry_port, tunnel)
                    if res.get('ok'):
                        print(f"  [{tun_label}] link-drop mid-xfer: freed via "
                              f"{res['mechanism']:8} in {res['detect_ms']:.0f} ms")
                        results.append(dict(scenario=scen_name, tunnel=tun_label,
                                            metric='resilience', **res))
            finally:
                tunnel.stop()
                dest.stop()
                time.sleep(0.2)

    if args.json:
        with open(args.json, 'w') as fh:
            json.dump(results, fh, indent=2)
        print(f"\nWrote {len(results)} records to {args.json}")

    return results


NETEM_HELP = """
Real kernel-level loss / reordering / duplication
==================================================
This benchmark shapes at the application layer (delay + bandwidth + jitter),
which is what TCP loss/reorder actually manifests as by the time fteproxy sees
the stream. To inject genuine packet loss/reordering below TCP, use the OS:

macOS (dummynet, needs sudo):
    sudo dnctl pipe 1 config bw 1Mbit/s delay 100ms plr 0.02
    echo 'dummynet in  proto tcp from any to any port <server_port> pipe 1' | sudo pfctl -f -
    echo 'dummynet out proto tcp from any to any port <server_port> pipe 1' | sudo pfctl -a com.apple/dummynet -f -
    sudo pfctl -E
    # ...run:  python3 benchmark.py --scenarios lan
    sudo pfctl -d ; sudo dnctl -q flush

Linux (netem, needs root, run the server in a netns or on a test box):
    sudo tc qdisc add dev lo root netem delay 100ms 25ms loss 2% reorder 5%
    # ...run the benchmark...
    sudo tc qdisc del dev lo root
"""


def main():
    ap = argparse.ArgumentParser(
        description="Performance & resilience benchmark for fteproxy.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument('--scenarios', nargs='+', default=DEFAULT_SCENARIOS,
                    metavar='NAME', help=f"any of: {', '.join(SCENARIOS)}")
    ap.add_argument('--sizes', nargs='+', type=_parse_size, default=DEFAULT_SIZES,
                    metavar='SIZE', help="payload sizes, e.g. 64 64K 1M 8M")
    ap.add_argument('--direction', choices=['echo', 'upload'], default='echo',
                    help="echo = round trip (both FTE dirs); upload = client->dest only")
    ap.add_argument('--repeat', type=int, default=3,
                    help="throughput repeats per cell (best is kept)")
    ap.add_argument('--baseline', action='store_true',
                    help="also run a plain-TCP relay of identical topology")
    ap.add_argument('--no-latency', dest='latency', action='store_false',
                    help="skip the interactive-latency test")
    ap.add_argument('--latency-count', type=int, default=50)
    ap.add_argument('--latency-size', type=int, default=64)
    ap.add_argument('--no-setup', dest='setup', action='store_false',
                    help="skip the connection-setup / negotiation test")
    ap.add_argument('--setup-count', type=int, default=20)
    ap.add_argument('--resilience', action='store_true',
                    help="run the mid-transfer link-drop resilience probe")
    ap.add_argument('--upstream-format', default=None,
                    help="fteproxy --upstream-format (e.g. manual-http-request)")
    ap.add_argument('--downstream-format', default=None)
    ap.add_argument('--record-layer-mode', choices=['hybrid', 'format'], default=None,
                    help="fteproxy --record-layer-mode for both endpoints "
                         "(default: fteproxy's own default, hybrid)")
    ap.add_argument('--json', default=None, metavar='PATH',
                    help="write raw results as JSON")
    ap.add_argument('--verbose', action='store_true',
                    help="let fteproxy subprocess logs through")
    ap.add_argument('--help-netem', action='store_true',
                    help="print how to add real kernel loss/reorder, then exit")
    args = ap.parse_args()

    if args.help_netem:
        print(NETEM_HELP)
        return

    for s in args.scenarios:
        if s not in SCENARIOS:
            ap.error(f"unknown scenario {s!r}; choose from {', '.join(SCENARIOS)}")

    try:
        import fteproxy  # noqa: F401
    except Exception as e:
        print(f"ERROR: cannot import fteproxy ({e}).")
        print("Install it into this interpreter, e.g.:  pip install -e .  (needs `fte`)")
        sys.exit(2)

    run_matrix(args)


def _parse_size(s):
    s = str(s).strip().upper()
    mult = 1
    if s.endswith('K'):
        mult, s = 1024, s[:-1]
    elif s.endswith('M'):
        mult, s = 1024 * 1024, s[:-1]
    elif s.endswith('G'):
        mult, s = 1024 * 1024 * 1024, s[:-1]
    return int(float(s) * mult)


if __name__ == '__main__':
    main()
