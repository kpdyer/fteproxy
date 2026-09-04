import json, os, sys, time
t0 = time.perf_counter()
import fteproxy, fteproxy.defs as D, fteproxy.handshake as H
imp = (time.perf_counter() - t0) * 1e3
t0 = time.perf_counter(); D.load_definitions(); defs_ms = (time.perf_counter() - t0) * 1e3
k = lambda: os.urandom(32)
ks = H.SessionKeys(k(), k(), k(), k(), k())
which = sys.argv[1]; mode = sys.argv[2]
t0 = time.perf_counter(); fteproxy._session_channel(which, mode, ks, is_client=False)
chan = (time.perf_counter() - t0) * 1e3
ks2 = H.SessionKeys(k(), k(), k(), k(), k())
t0 = time.perf_counter(); fteproxy._session_channel(which, mode, ks2, is_client=False)
warm = (time.perf_counter() - t0) * 1e3
print(json.dumps({'base': which, 'mode': mode, 'import_ms': imp,
                  'load_definitions_ms': defs_ms, 'channel_cold_ms': chan,
                  'channel_warm_ms': warm}))
