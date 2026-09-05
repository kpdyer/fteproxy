#!/bin/bash
# SOCKS5 browsing through fteproxy. The server dials allowed destinations.
# This proxies applications configured to use the local SOCKS5 listener.

MODE="${1:-help}"
URI="$2"
SOCKS_PORT="${3:-1080}"

case "$MODE" in
    server)
        echo "Starting FTE server for web proxying..."
        echo "  FTE listening on wildcard port 8080"
        echo "  Clients may reach: global unicast destinations"
        echo ""
        echo "'--allow any' uses the same address restrictions as no allow rules."
        echo "Private and loopback destinations need an explicit IP or CIDR rule."
        echo "Copy the reported connection.txt file privately to the client."
        echo ""
        python3 -m fteproxy server --allow any
        ;;

    client)
        if [ -z "$URI" ]; then
            echo "Error: pass the URI from the server's connection.txt, e.g."
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
        echo "destination name through the tunnel for the server to resolve."
        echo "Other application traffic is unaffected by this proxy setting."
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
        echo "  # Copy connection.txt privately; set a reachable endpoint with keygen --advertise."
        echo ""
        echo "  # On client:"
        echo "  $0 client 'fte://<server-id>@192.168.1.100:8080'"
        echo "  curl --socks5-hostname 127.0.0.1:1080 https://example.com/"
        ;;
esac
