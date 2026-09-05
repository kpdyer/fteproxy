# Basic forwarding example

`start_server.sh` and `start_client.sh` pass all arguments to
`python3 -m fteproxy server` and `python3 -m fteproxy client`.
Install fteproxy, then run the following from `examples/basic` in four terminals.
The ports must be free, and `nc` must be installed.

1. Start the server:

   ```bash
   ./start_server.sh --listen 127.0.0.1:8080 --advertise 127.0.0.1:8080 --allow 127.0.0.1:8081
   ```

   It saves `server.key` and `connection.txt` in the state directory and reports
   their paths. The explicit allow rule permits the loopback destination.

2. Start a destination that displays received bytes:

   ```bash
   nc -l 8081
   ```

3. Start the client:

   ```bash
   ./start_client.sh -L 8079:127.0.0.1:8081
   ```

   With no explicit connection source or `FTEPROXY_URI`, the client reads
   `connection.txt` from the same state directory as the server.

4. Send a message:

   ```bash
   echo 'Hello through FTE!' | nc 127.0.0.1 8079
   ```

The message appears in terminal 2. Netcat options and EOF behavior vary; stop it
with Ctrl+C if it stays open. Stop the client and server when finished.

```text
nc -> client :8079 -> encrypted tunnel -> server :8080 -> nc :8081
```

The destination `127.0.0.1:8081` is relative to the server. This example selects
HTTP and hybrid mode: FTE headers followed by encrypted, chunked bodies.

For a remote server, choose its reachable `--listen` and `--advertise` addresses,
copy `connection.txt` privately, and use `--connection-file FILE` on the client.
See [CLI setup and destination rules](../../README.md).
