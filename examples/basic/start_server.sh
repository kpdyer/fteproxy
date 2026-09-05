#!/bin/bash
# Pass all arguments to the server, for example:
#   ./start_server.sh --listen 127.0.0.1:8080 --allow 127.0.0.1:8081
# First startup saves server.key and connection.txt in the state directory;
# server reports their paths without printing the connection capability.

exec python3 -m fteproxy server "$@"
