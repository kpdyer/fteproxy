#!/usr/bin/env python3
import json
import glob
import os
import statistics

S = os.path.dirname(os.path.abspath(__file__))
R = os.path.join(S, 'raw')


def load(pat):
    return [json.load(open(p)) for p in sorted(glob.glob(os.path.join(R, pat)))]


def pr(label, vals, unit='', fmt='%.2f'):
    vals = sorted(vals)
    print(('%-46s p50 ' + fmt + '  (' + fmt + '-' + fmt + ') %s')
          % (label, statistics.median(vals), vals[0], vals[-1], unit))


print('=== end to end (benchmark.py, 3 runs) ===')
for tag, pat in (('http/hybrid', 'http_hybrid_*.json'),
                 ('smtp/format', 'smtp_format_*.json'),
                 ('dns/format', 'dns_format_*.json')):
    runs = load(pat)
    kinds = {}
    for run in runs:
        for rec in run:
            key = (rec.get('tunnel'), rec.get('metric'), rec.get('size'))
            kinds.setdefault(key, []).append(rec)
    for key in sorted(kinds, key=lambda k: (str(k[0]), str(k[1]), k[2] or 0)):
        recs = kinds[key]
        stack, workload, nbytes = key
        if workload == 'throughput':
            pr('%s %s %s %s Mbit/s' % (tag, stack, workload, nbytes),
               [r['mbit_s'] for r in recs])
        elif workload == 'latency':
            pr('%s %s rtt p50 ms' % (tag, stack), [r['p50_ms'] for r in recs])
            pr('%s %s rtt p90 ms' % (tag, stack), [r['p90_ms'] for r in recs])
        elif workload == 'setup':
            pr('%s %s setup p50 ms' % (tag, stack), [r['p50_ms'] for r in recs])
            pr('%s %s setup min ms' % (tag, stack), [r['min_ms'] for r in recs])

print()
print('=== record layer: hybrid round trips ===')
recs = load('rec_*.json')
for base in ('http', 'smtp'):
    for i, row in enumerate(recs[0]['hybrid'][base]):
        n = row['bytes']
        ms = [r['hybrid'][base][i]['p50_ms'] for r in recs]
        mb = [r['hybrid'][base][i]['mb_s'] for r in recs]
        pr('%s hybrid %d B  ms/record' % (base, n), ms, fmt='%.3f')
        pr('%s hybrid %d B  MB/s' % (base, n), mb, fmt='%.1f')
        print('%-46s wire %d  expansion %.2fx' %
              ('', row['wire'], row['expansion']))

print()
print('=== record layer: header/body split ===')
for base in ('http', 'smtp'):
    for n in ('262144', '1048576'):
        s0 = recs[0]['split'][base][n]
        print('%s header_len=%d capacity=%d body=%s' %
              (base, s0['header_length'], s0['header_capacity'], n))
        pr('  seal ms', [r['split'][base][n]['seal']['p50_ms'] for r in recs], fmt='%.3f')
        pr('  open ms', [r['split'][base][n]['open']['p50_ms'] for r in recs], fmt='%.3f')
        pr('  body enc ms', [r['split'][base][n]['body_encrypt']['p50_ms'] for r in recs], fmt='%.3f')
        pr('  body dec ms', [r['split'][base][n]['body_decrypt']['p50_ms'] for r in recs], fmt='%.3f')

print()
print('=== record layer: format mode per covertext length ===')
for name in ('http-request', 'dns-request'):
    print(name)
    for i, row in enumerate(recs[0]['per_length'][name]):
        ms = [r['per_length'][name][i]['ms'] for r in recs]
        mb = [r['per_length'][name][i]['mb_s'] for r in recs]
        enc = [r['per_length'][name][i]['encode_ms'] for r in recs]
        print('  len %4d payload %4d wire %4d exp %5.2fx  ms %.3f (%.3f-%.3f) '
              'MB/s %.2f  enc-only %.3f'
              % (row['length'], row['payload'], row['wire'], row['expansion'],
                 statistics.median(ms), min(ms), max(ms),
                 statistics.median(mb), statistics.median(enc)))

print()
print('=== record layer: 64 B round trip, format mode ===')
for base in ('http', 'smtp', 'dns'):
    row = recs[0]['format_rt'][base]
    pr('%s format 64 B ms/record' % base,
       [r['format_rt'][base]['p50_ms'] for r in recs], fmt='%.3f')
    print('%-46s wire %d expansion %.2fx' % ('', row['wire'], row['expansion']))

print()
print('=== DFA compile ===')
for name in ('http-request', 'dns-request'):
    print(name)
    for i, row in enumerate(recs[0]['dfa'][name]['per_length']):
        c = [r['dfa'][name]['per_length'][i]['compile_ms'] for r in recs]
        k = [r['dfa'][name]['per_length'][i]['keyed_cipher_ms'] for r in recs]
        ca = [r['dfa'][name]['per_length'][i]['cached_ms'] for r in recs]
        print('  len %4d compile %.2f (%.2f-%.2f) ms  cached lookup %.5f ms  '
              'keyed cipher %.4f ms'
              % (row['length'], statistics.median(c), min(c), max(c),
                 statistics.median(ca), statistics.median(k)))
    pr('  all eight ms', [r['dfa'][name]['all_lengths_ms'] for r in recs])

print()
print('=== channel setup (cold vs warm cache) ===')
for key in recs[0]['channel']:
    pr('%s cold ms' % key, [r['channel'][key]['cold_ms'] for r in recs])
    pr('%s warm ms' % key, [r['channel'][key]['warm_ms'] for r in recs], fmt='%.4f')

print()
print('=== client startup pre-warm (cli.check_format) ===')
for key in recs[0]['prewarm']:
    pr('%s ms' % key, [r['prewarm'][key] for r in recs])

print()
print('=== first tunnelled connection vs steady state (end to end) ===')
firsts = load('first_*.json')
for key in firsts[0]:
    pr('%s first ms' % key, [f[key]['first_ms'] for f in firsts])
    pr('%s steady p50 ms' % key, [f[key]['steady_p50_ms'] for f in firsts])
