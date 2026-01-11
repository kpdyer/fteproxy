#!/bin/bash
#
# FTE Netcat Demo
# ===============
#
# Demonstrates fteproxy relay mode with netcat for interactive testing.
#
# Architecture:
#
#   [netcat client] --> [fteproxy client:8079] --FTE--> [fteproxy server:8080] --> [netcat server:8081]
#
# All traffic between the fteproxy client and server is FTE-encoded.
#

set -e

# Configuration
CLIENT_IP=127.0.0.1
CLIENT_PORT=8079
SERVER_IP=127.0.0.1
SERVER_PORT=8080
PROXY_IP=127.0.0.1
PROXY_PORT=8081

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    kill $FTEPROXY_CLIENT_PID 2>/dev/null || true
    kill $FTEPROXY_SERVER_PID 2>/dev/null || true
    kill $NC_SERVER_PID 2>/dev/null || true
    echo "Done."
}

trap cleanup EXIT

echo "=================================="
echo "FTE Netcat Demo"
echo "=================================="
echo ""
echo "Starting fteproxy server on $SERVER_IP:$SERVER_PORT..."
python -m fteproxy --mode server --quiet \
    --server_ip $SERVER_IP --server_port $SERVER_PORT \
    --proxy_ip $PROXY_IP --proxy_port $PROXY_PORT &
FTEPROXY_SERVER_PID=$!
sleep 1

echo "Starting fteproxy client on $CLIENT_IP:$CLIENT_PORT..."
python -m fteproxy --mode client --quiet \
    --client_ip $CLIENT_IP --client_port $CLIENT_PORT \
    --server_ip $SERVER_IP --server_port $SERVER_PORT &
FTEPROXY_CLIENT_PID=$!
sleep 1

echo "Starting netcat server on $PROXY_IP:$PROXY_PORT..."
echo ""
echo "=================================="
echo "Ready! In another terminal, run:"
echo "  nc $CLIENT_IP $CLIENT_PORT"
echo ""
echo "Type messages and they will appear below."
echo "Press Ctrl+C to exit."
echo "=================================="
echo ""

# Use nc with portable options (-l for listen)
# On macOS: nc -l $PROXY_PORT
# On Linux: nc -l -p $PROXY_PORT
if nc -h 2>&1 | grep -q '\-p'; then
    nc -l -p $PROXY_PORT
else
    nc -l $PROXY_PORT
fi
