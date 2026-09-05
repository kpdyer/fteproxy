#!/usr/bin/env python3
"""Archived record-layer microbenchmarks; no sockets.

Report JSON medians from session/record-layer calls. See README.md for the
measured revision and local paths. hybrid_split still uses the base grammar,
so it does not reproduce the current HTTP hybrid header path.
"""
import json
import os
import statistics
import sys
import time

import fteproxy
import fteproxy.cli
import fteproxy.defs as D
import fteproxy.handshake as H
import fteproxy.record_layer as RL


def session_keys():
    k = lambda: os.urandom(32)
    return H.SessionKeys(k(), k(), k(), k(), k())


def channel(base, mode):
    """(client encoder, server decoder) for one direction of a session."""
    ks = session_keys()
    enc, _ = fteproxy._session_channel(base, mode, ks, is_client=True)
    _, dec = fteproxy._session_channel(base, mode, ks, is_client=False)
    return enc, dec


def med(samples):
    samples = sorted(samples)
    return {'p50_ms': statistics.median(samples) * 1e3,
            'min_ms': samples[0] * 1e3,
            'max_ms': samples[-1] * 1e3,
            'n': len(samples)}


def roundtrip(base, mode, nbytes, iters):
    enc, dec = channel(base, mode)
    msg = os.urandom(nbytes)
    wire_bytes = None
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter()
        enc.push(msg)
        wire = enc.pop()
        dec.push(wire)
        out = dec.pop()
        samples.append(time.perf_counter() - t0)
        assert out == msg, (len(out), nbytes)
        wire_bytes = len(wire)
    r = med(samples)
    r.update(bytes=nbytes, wire=wire_bytes,
             expansion=wire_bytes / float(nbytes),
             mb_s=(nbytes / 1e6) / (r['p50_ms'] / 1e3))
    return r


def hybrid_split(base, nbytes, iters):
    """Time base-regex header sealing/opening and body encryption/decryption separately."""
    spec = D._spec(base + '-request')
    hlen = fteproxy.hybrid_header_length(spec)
    key = os.urandom(32)
    header = fteproxy._spec_cipher(spec, hlen, key)
    body = fteproxy._make_body_cipher(os.urandom(32))
    payload = os.urandom(nbytes)
    import struct
    four = struct.pack('>I', nbytes + 1)

    seal, open_, benc, bdec = [], [], [], []
    for i in range(iters):
        t0 = time.perf_counter()
        sealed = RL._seal(header, four, i)
        t1 = time.perf_counter()
        plain = header.decrypt(sealed)
        RL._unseal(plain, i)
        t2 = time.perf_counter()
        framed = body.encrypt(b'\x00' + payload, i)
        t3 = time.perf_counter()
        body.decrypt(framed, i)
        t4 = time.perf_counter()
        seal.append(t1 - t0)
        open_.append(t2 - t1)
        benc.append(t3 - t2)
        bdec.append(t4 - t3)
    return {'header_length': hlen,
            'header_capacity': header.max_plaintext_bytes,
            'seal': med(seal), 'open': med(open_),
            'body_encrypt': med(benc), 'body_decrypt': med(bdec),
            'body_bytes': nbytes}


def per_length(name, iters):
    """format-mode cost of one record at each covertext length."""
    spec = D._spec(name)
    key = os.urandom(32)
    rows = []
    for length in D.spec_allowed_lengths(spec):
        cipher = fteproxy._spec_cipher(spec, length, key)
        cap = cipher.max_plaintext_bytes - RL._SEAL_OVERHEAD - RL._TYPE_LEN
        msg = b'\x01' + os.urandom(cap)          # type byte + payload
        both, enc_only = [], []
        for i in range(iters):
            t0 = time.perf_counter()
            ct = RL._seal(cipher, msg, i)
            t1 = time.perf_counter()
            pt = cipher.decrypt(ct)
            assert RL._unseal(pt, i) == msg
            t2 = time.perf_counter()
            both.append(t2 - t0)
            enc_only.append(t1 - t0)
        r = med(both)
        rows.append({'length': length, 'payload': cap, 'wire': len(ct),
                     'expansion': len(ct) / float(cap),
                     'ms': r['p50_ms'], 'min_ms': r['min_ms'],
                     'max_ms': r['max_ms'],
                     'mb_s': (cap / 1e6) / (r['p50_ms'] / 1e3),
                     'encode_ms': med(enc_only)['p50_ms']})
    return rows


def dfa_compile(name):
    """Time uncached per-length compilation, cached lookup, and keyed-cipher setup."""
    spec = D._spec(name)
    pattern = spec['regex']
    framing = D.spec_framing(spec)
    rows = []
    total = 0.0
    for length in D.spec_allowed_lengths(spec):
        mlen = fteproxy._message_length(framing, length)
        fteproxy._regex_format.cache_clear()
        t0 = time.perf_counter()
        fteproxy._regex_format(pattern, mlen)
        dt = time.perf_counter() - t0
        total += dt
        t0 = time.perf_counter()
        fteproxy._regex_format(pattern, mlen)
        warm = time.perf_counter() - t0
        # keyed cipher on top of a cached DFA
        t0 = time.perf_counter()
        fteproxy._spec_cipher(spec, length, b'\x02' * 32)
        keyed = time.perf_counter() - t0
        rows.append({'length': length, 'compile_ms': dt * 1e3,
                     'cached_ms': warm * 1e3, 'keyed_cipher_ms': keyed * 1e3})
    return {'per_length': rows, 'all_lengths_ms': total * 1e3}


def channel_setup(base, mode):
    ks = session_keys()
    fteproxy._regex_format.cache_clear()
    fteproxy._hybrid_header_length.cache_clear()
    t0 = time.perf_counter()
    fteproxy._session_channel(base, mode, ks, is_client=True)
    cold = time.perf_counter() - t0
    warm_samples = []
    for _ in range(10):
        ks2 = session_keys()
        t0 = time.perf_counter()
        fteproxy._session_channel(base, mode, ks2, is_client=True)
        warm_samples.append(time.perf_counter() - t0)
    return {'cold_ms': cold * 1e3, 'warm_ms': med(warm_samples)['p50_ms']}


def prewarm(base):
    fteproxy._regex_format.cache_clear()
    t0 = time.perf_counter()
    fteproxy.cli.check_format(base)
    return (time.perf_counter() - t0) * 1e3


def main():
    out = {}
    # 1. hybrid records, default http (200 B header) and smtp (80 B header)
    out['hybrid'] = {}
    for base in ('http', 'smtp'):
        rows = []
        for nbytes, iters in ((64, 200), (4096, 200), (262144, 60), (1048576, 30)):
            rows.append(roundtrip(base, H.MODE_HYBRID, nbytes, iters))
        out['hybrid'][base] = rows
    # 2. header vs body split
    out['split'] = {base: {str(n): hybrid_split(base, n, iters)
                           for n, iters in ((262144, 60), (1048576, 30))}
                    for base in ('http', 'smtp')}
    # 3. format mode per covertext length
    out['per_length'] = {name: per_length(name, 120)
                         for name in ('http-request', 'dns-request')}
    # 4. format-mode whole-record round trips at 64 B (interactive)
    out['format_rt'] = {}
    for base in ('http', 'smtp', 'dns'):
        out['format_rt'][base] = roundtrip(base, H.MODE_FORMAT, 64, 200)
    # 5. DFA compiles
    out['dfa'] = {name: dfa_compile(name) for name in ('http-request', 'dns-request')}
    # 6. channel setup cold/warm
    out['channel'] = {
        'http/hybrid': channel_setup('http', H.MODE_HYBRID),
        'http/format': channel_setup('http', H.MODE_FORMAT),
        'dns/format': channel_setup('dns', H.MODE_FORMAT),
        'smtp/format': channel_setup('smtp', H.MODE_FORMAT),
    }
    # 7. client startup pre-warm
    out['prewarm'] = {base: prewarm(base)
                      for base in ('http', 'ftp', 'smtp', 'sip', 'dns')}
    fteproxy._regex_format.cache_clear()
    t0 = time.perf_counter()
    for base in ('http', 'ftp', 'smtp', 'sip', 'dns'):
        fteproxy.cli.check_format(base)
    out['prewarm']['all'] = (time.perf_counter() - t0) * 1e3
    json.dump(out, sys.stdout, indent=1)


if __name__ == '__main__':
    main()
