# Local netcat demo

From `examples/netcat`, run:

```bash
./demo.sh
```

Once it reports readiness, send from another terminal:

```bash
echo 'Hello, FTE!' | nc 127.0.0.1 8079
```

The message appears in the demo terminal. Install fteproxy and netcat first,
and ensure ports 8079–8081 are free. Netcat options vary by implementation;
the script tries a persistent listener and falls back to a single connection.

| Port | Purpose |
| --- | --- |
| 8079 | Client forward on loopback |
| 8080 | FTE server on loopback |
| 8081 | Netcat destination; `nc` may bind all interfaces |

```text
sender -> client :8079 -> encrypted tunnel -> server :8080 -> netcat :8081
```

The client requests `127.0.0.1:8081`; the server permits it through an explicit
allow rule. With current defaults, the tunnel uses HTTP headers and encrypted
chunked bodies. This demonstrates transport, not resistance to traffic analysis.

The script uses a temporary state directory for its generated identity and
connection file. Press Ctrl+C to stop its background processes and remove that
directory. If the sending netcat stays open, stop it with Ctrl+C too.
