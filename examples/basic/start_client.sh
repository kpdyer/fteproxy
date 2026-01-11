#!/bin/bash
# Start fteproxy client with default settings

SERVER_IP="${1:-127.0.0.1}"

echo "Starting fteproxy client..."
echo "  Listening for plaintext on: 127.0.0.1:8079"
echo "  Connecting to FTE server: $SERVER_IP:8080"
echo ""

fteproxy --mode client \
    --client_ip 127.0.0.1 \
    --client_port 8079 \
    --server_ip "$SERVER_IP" \
    --server_port 8080
