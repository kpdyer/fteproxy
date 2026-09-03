#!/bin/bash
# Web Browsing Over FTE
#
# Use fteproxy to tunnel web traffic. This is useful when:
# - You need to access blocked websites
# - You want to hide your browsing patterns
# - You're on a network that inspects traffic
#
# No proxy software is needed on the server: the client speaks SOCKS5 to your
# browser and the server dials whatever the browser asks for.

MODE="${1:-help}"
URI="$2"
SOCKS_PORT="${3:-1080}"

case "$MODE" in
    server)
        echo "Starting FTE server for web proxying..."
        echo "  FTE listening on: 0.0.0.0:8080"
        echo "  Clients may reach: any destination"
        echo ""
        echo "'--allow any' means exactly that: whoever holds the connection"
        echo "string can have this server dial any address and port, including"
        echo "its own loopback and private networks. Plain 'fteproxy server'"
        echo "with no rule reaches the whole public internet but refuses this"
        echo "host's own loopback and link-local addresses; prefer it unless"
        echo "you really need loopback reachable."
        echo ""
        python3 -m fteproxy server --allow any
        ;;

    client)
        if [ -z "$URI" ]; then
            echo "Error: pass the connection string the server printed, e.g."
            echo "  $0 client 'fte://<server-id>@192.168.1.100:8080'"
            exit 2
        fi
        echo "Starting FTE client for web proxying..."
        echo "  SOCKS5 on: 127.0.0.1:$SOCKS_PORT"
        echo ""
        echo "Configure your browser to use:"
        echo "  SOCKS5 proxy: 127.0.0.1 port $SOCKS_PORT"
        echo ""
        echo "Or use curl:"
        echo "  curl --socks5-hostname 127.0.0.1:$SOCKS_PORT https://example.com/"
        echo ""
        echo "--socks5-hostname (and a browser's 'proxy DNS' setting) sends the"
        echo "name through the tunnel for the server to resolve, so lookups do"
        echo "not leak around the proxy."
        echo ""
        python3 -m fteproxy client "$URI" -D "$SOCKS_PORT"
        ;;

    *)
        echo "Web Proxy Over FTE"
        echo "=================="
        echo ""
        echo "Usage:"
        echo "  $0 server                                    - Start server"
        echo "  $0 client <connection-string> [socks-port]   - Start client (default port: 1080)"
        echo ""
        echo "Example:"
        echo "  # On server:"
        echo "  $0 server"
        echo "  # It prints a connection string; copy it to the client."
        echo ""
        echo "  # On client:"
        echo "  $0 client 'fte://<server-id>@192.168.1.100:8080'"
        echo "  curl --socks5-hostname 127.0.0.1:1080 https://example.com/"
        ;;
esac
