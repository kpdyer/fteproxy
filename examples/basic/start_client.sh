#!/bin/bash
# Pass all arguments to the client, for example:
#   ./start_client.sh --connection-file ./connection.txt -D 1080
# Without an explicit connection source, use FTEPROXY_URI or the state
# directory's connection.txt. With no -D/-L, listen on SOCKS5 127.0.0.1:1080.

exec python3 -m fteproxy client "$@"
