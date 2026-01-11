#!/bin/bash
# Web Browsing Over FTE
#
# Use fteproxy to tunnel web traffic. This is useful when:
# - You need to access blocked websites
# - You want to hide your browsing patterns
# - You're on a network that inspects traffic
#
# Prerequisites:
# - A proxy server (like tinyproxy, squid, or privoxy) on the server
# - Or direct forwarding to a web server

MODE="${1:-help}"
SERVER_IP="${2:-127.0.0.1}"
PROXY_PORT="${3:-8888}"

case "$MODE" in
    server)
        echo "Starting FTE server for web proxy..."
        echo "  FTE listening on: 0.0.0.0:8080"
        echo "  Forwarding to proxy: 127.0.0.1:$PROXY_PORT"
        echo ""
        echo "Make sure your web proxy is running on port $PROXY_PORT"
        echo "(e.g., tinyproxy, squid, privoxy)"
        echo ""
        python -m fteproxy --mode server \
            --server_ip 0.0.0.0 \
            --server_port 8080 \
            --proxy_ip 127.0.0.1 \
            --proxy_port "$PROXY_PORT"
        ;;
    
    client)
        echo "Starting FTE client for web proxy..."
        echo "  Local proxy port: 8079"
        echo "  FTE server: $SERVER_IP:8080"
        echo ""
        echo "Configure your browser to use:"
        echo "  HTTP Proxy: localhost:8079"
        echo ""
        echo "Or use curl:"
        echo "  curl -x http://localhost:8079 https://example.com"
        echo ""
        python -m fteproxy --mode client \
            --client_ip 127.0.0.1 \
            --client_port 8079 \
            --server_ip "$SERVER_IP" \
            --server_port 8080
        ;;
    
    *)
        echo "Web Proxy Over FTE"
        echo "=================="
        echo ""
        echo "Usage:"
        echo "  $0 server [proxy-port]   - Start server (default proxy port: 8888)"
        echo "  $0 client <server-ip>    - Start client"
        echo ""
        echo "Example:"
        echo "  # On server (with tinyproxy on port 8888):"
        echo "  $0 server"
        echo ""
        echo "  # On client:"
        echo "  $0 client 192.168.1.100"
        echo "  curl -x http://localhost:8079 https://example.com"
        ;;
esac
