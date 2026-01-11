#!/bin/bash
# Start fteproxy server with default settings

echo "Starting fteproxy server..."
echo "  Listening for FTE connections on: 0.0.0.0:8080"
echo "  Forwarding plaintext to: 127.0.0.1:8081"
echo ""

python -m fteproxy --mode server \
    --server_ip 0.0.0.0 \
    --server_port 8080 \
    --proxy_ip 127.0.0.1 \
    --proxy_port 8081
