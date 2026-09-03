#!/bin/bash
# Start an fteproxy client. Every argument is passed straight through, e.g.
#   ./start_client.sh fte://<server-id>@203.0.113.5:8080 -D 1080
#
# Without a URI argument the client takes one from $FTEPROXY_URI, then from
# connection.txt in the state directory -- so on the host that ran the server
# no argument is needed at all. With neither -D nor -L it opens a SOCKS5
# listener on 127.0.0.1:1080.

exec python3 -m fteproxy client "$@"
