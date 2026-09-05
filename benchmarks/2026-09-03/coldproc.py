import sys, time, json
import fteproxy, fteproxy.defs as D
name, length = sys.argv[1], int(sys.argv[2])
spec = D._spec(name)
mlen = fteproxy._message_length(D.spec_framing(spec), length)
t0 = time.perf_counter()
fteproxy._regex_format(spec['regex'], mlen)
first = (time.perf_counter() - t0) * 1e3
# Time a different length after definitions have loaded. The maximum-length
# DFA may already be cached by loading, so this is not always a cold compile.
lengths = [l for l in D.spec_allowed_lengths(spec) if l != length]
l2 = lengths[-1]
m2 = fteproxy._message_length(D.spec_framing(spec), l2)
t0 = time.perf_counter()
fteproxy._regex_format(spec['regex'], m2)
second = (time.perf_counter() - t0) * 1e3
print(json.dumps({'name': name, 'length': length, 'first_ms': first,
                  'second_length': l2, 'second_ms': second}))
