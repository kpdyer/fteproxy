#!/bin/bash
#
# FTE Proxy Netcat Demo
#
# Demonstrates fteproxy by tunneling netcat traffic through FTE encoding.
# Run this script, then in another terminal: echo "Hello" | nc localhost 8079
#

set -e

# Configuration
CLIENT_IP=127.0.0.1
CLIENT_PORT=8079
SERVER_IP=127.0.0.1
SERVER_PORT=8080
PROXY_IP=127.0.0.1
PROXY_PORT=8081

# Track background PIDs for cleanup
PIDS=()

cleanup() {
    echo ""
    echo "Cleaning up..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    exit 0
}

trap cleanup EXIT INT TERM

echo "================================================================"
echo "                   FTE Proxy Netcat Demo                        "
echo "================================================================"
echo ""
echo "Traffic flow:"
echo ""
echo "  [You] -> :$CLIENT_PORT -> [FTE Client] -> [FTE Server] -> :$PROXY_PORT -> [nc]"
echo "           plaintext       FTE encoded       plaintext"
echo ""
echo "================================================================"
echo ""

# Start fteproxy server
echo "[1/3] Starting FTE server (listening on :$SERVER_PORT, forwarding to :$PROXY_PORT)..."
python3 -m fteproxy --mode server --quiet \
    --server_ip "$SERVER_IP" --server_port "$SERVER_PORT" \
    --proxy_ip "$PROXY_IP" --proxy_port "$PROXY_PORT" &
PIDS+=($!)
sleep 0.5

# Start fteproxy client  
echo "[2/3] Starting FTE client (listening on :$CLIENT_PORT, connecting to :$SERVER_PORT)..."
python3 -m fteproxy --mode client --quiet \
    --client_ip "$CLIENT_IP" --client_port "$CLIENT_PORT" \
    --server_ip "$SERVER_IP" --server_port "$SERVER_PORT" &
PIDS+=($!)
sleep 0.5

# Start netcat listener
echo "[3/3] Starting netcat listener on :$PROXY_PORT..."
echo ""
echo "================================================================"
echo "Ready! In another terminal, run:"
echo ""
echo "    echo 'Hello, FTE!' | nc $CLIENT_IP $CLIENT_PORT"
echo ""
echo "You should see the message appear below."
echo "Press Ctrl+C to stop."
echo "================================================================"
echo ""

# Use nc (more portable than netcat)
nc -l -k "$PROXY_PORT" 2>/dev/null || nc -l "$PROXY_PORT"
