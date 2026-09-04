import os, time, statistics, json
import fteproxy, fteproxy.defs as D, fteproxy.record_layer as RL

def med(fn, n=200):
    s = []
    for i in range(n):
        t0 = time.perf_counter(); fn(i); s.append((time.perf_counter()-t0)*1e3)
    return statistics.median(s)

out = {}
# (a) seal padding cost at the http hybrid header length
spec = D._spec('http-request')
key = os.urandom(32)
for L in (200, 700):
    c = fteproxy._spec_cipher(spec, L, key)
    cap = c.max_plaintext_bytes
    raw = med(lambda i: c.encrypt(b'\x00' * 16))
    padded = med(lambda i: c.encrypt(b'\x00' * cap))
    seal = med(lambda i: RL._seal(c, b'\x00' * 4, i))
    out['seal@%d' % L] = {'capacity': cap, 'encrypt16_ms': raw,
                          'encrypt_full_ms': padded, 'seal_ms': seal}
# (b) per-length capacity for every shipped format, and the shortest length
#     whose record carries 64 payload bytes
out['capacities'] = {}
for base in ('http', 'smtp', 'dns', 'ftp', 'sip'):
    name = base + '-request'
    sp = D._spec(name)
    caps = {}
    for L in D.spec_allowed_lengths(sp):
        c = fteproxy._spec_cipher(sp, L, key)
        caps[L] = c.max_plaintext_bytes - RL._SEAL_OVERHEAD - RL._TYPE_LEN
    fit = [L for L, v in caps.items() if v >= 64]
    out['capacities'][name] = {'caps': caps, 'shortest_for_64B': fit[0] if fit else None}
# (c) one 64-byte record at that length, encode+decode
out['interactive'] = {}
for base in ('http', 'smtp', 'dns'):
    name = base + '-request'
    sp = D._spec(name)
    L = out['capacities'][name]['shortest_for_64B']
    c = fteproxy._spec_cipher(sp, L, key)
    msg = b'\x01' + b'p' * 64
    def rt(i, c=c, msg=msg):
        ct = c.encrypt(RL._LEN.pack(len(msg)) + RL._SEQ.pack(i) + msg +
                       os.urandom(c.max_plaintext_bytes - RL._SEAL_OVERHEAD - len(msg)))
        c.decrypt(ct)
    out['interactive'][base] = {'length': L, 'ms': med(rt),
                                'wire': L, 'expansion': L / 64.0}
print(json.dumps(out, indent=1))
