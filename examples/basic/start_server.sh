#!/bin/bash
# Start an fteproxy server. Every argument is passed straight through, e.g.
#   ./start_server.sh --listen :8080 --allow 127.0.0.1:8081
#
# The first start generates the server's keypair in the state directory
# (~/.local/state/fteproxy by default) and prints the connection string
# clients need, which it also writes to connection.txt beside the key.

exec python3 -m fteproxy server "$@"
