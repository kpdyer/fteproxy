#!/usr/bin/env python3
"""Archive helper: first completed tunnel handshake versus later connections.

Avoid probing the client forward, which would warm both endpoints. Probe only
the raw server port, then use a fixed client settle delay. See README.md for
the measured revision and the script's machine-specific paths.
"""
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = '/Users/kpdyer/sandbox/github/fteproxy/.claude/worktrees/fteproxy-cli-ergonomics-476910'
sys.path.insert(0, ROOT)
import benchmark as B


def one_connection(entry_port):
    t0 = time.perf_counter()
    app = socket.create_connection(('127.0.0.1', entry_port), timeout=30)
    app.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    app.settimeout(30)
    app.sendall(b'!')
    back = B.recv_n(app, 1)
    dt = (time.perf_counter() - t0) * 1e3
    app.close()
    assert len(back) == 1
    return dt


def row(format=None, mode=None, steady=20, settle=3.0):
    dest = B.LoopServer(B.free_port(), mode='echo')
    dest.start()
    state = tempfile.mkdtemp(prefix='fteproxy-firstconn-')
    sport, eport = B.free_port(), B.free_port()
    py = sys.executable
    devnull = subprocess.DEVNULL
    srv = subprocess.Popen(
        [py, '-m', 'fteproxy', 'server', '-q',
         '--listen', '127.0.0.1:%d' % sport,
         '--advertise', '127.0.0.1:%d' % sport,
         '--allow', '127.0.0.1:%d' % dest.port,
         '--state-dir', state], stdout=devnull, stderr=devnull)
    B.wait_listening(sport)          # server socket only: no handshake
    uri = open(os.path.join(state, 'connection.txt')).read().strip()
    cmd = [py, '-m', 'fteproxy', 'client', uri, '-q', '--no-check',
           '-L', '127.0.0.1:%d:127.0.0.1:%d' % (eport, dest.port),
           '--state-dir', state]
    if format:
        cmd += ['--format', format]
    if mode:
        cmd += ['--mode', mode]
    cli = subprocess.Popen(cmd, stdout=devnull, stderr=devnull)
    time.sleep(settle)               # NOT wait_listening: that would warm both
    try:
        first = one_connection(eport)
        rest = sorted(one_connection(eport) for _ in range(steady))
    finally:
        for p in (cli, srv):
            p.terminate()
        for p in (cli, srv):
            p.wait(timeout=5)
        dest.stop()
    return {'first_ms': first, 'steady_p50_ms': statistics.median(rest),
            'steady_min_ms': rest[0], 'n': len(rest)}


def main():
    out = {}
    out['http/hybrid (default)'] = row()
    out['smtp/format'] = row(format='smtp', mode='format')
    out['dns/format'] = row(format='dns', mode='format')
    out['sip/format'] = row(format='sip', mode='format')
    json.dump(out, sys.stdout, indent=1)


if __name__ == '__main__':
    main()
