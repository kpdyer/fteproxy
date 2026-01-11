#!/bin/bash
# SSH Tunnel Over FTE
# 
# This script sets up an SSH tunnel through fteproxy.
# Traffic will appear as HTTP-like patterns to network observers.
#
# Usage:
#   Server: ./ssh_tunnel.sh server
#   Client: ./ssh_tunnel.sh client <server-ip>

MODE="${1:-help}"
SERVER_IP="${2:-127.0.0.1}"

case "$MODE" in
    server)
        echo "Starting FTE server for SSH tunneling..."
        echo "  FTE listening on: 0.0.0.0:8080"
        echo "  Forwarding to SSH: 127.0.0.1:22"
        echo ""
        echo "Make sure sshd is running on port 22"
        echo ""
        python -m fteproxy --mode server \
            --server_ip 0.0.0.0 \
            --server_port 8080 \
            --proxy_ip 127.0.0.1 \
            --proxy_port 22
        ;;
    
    client)
        echo "Starting FTE client for SSH tunneling..."
        echo "  Local port: 8079"
        echo "  FTE server: $SERVER_IP:8080"
        echo ""
        echo "To connect via SSH, run:"
        echo "  ssh -p 8079 user@localhost"
        echo ""
        python -m fteproxy --mode client \
            --client_ip 127.0.0.1 \
            --client_port 8079 \
            --server_ip "$SERVER_IP" \
            --server_port 8080
        ;;
    
    *)
        echo "SSH Tunnel Over FTE"
        echo "==================="
        echo ""
        echo "Usage:"
        echo "  $0 server              - Start server (forwards to local SSH)"
        echo "  $0 client <server-ip>  - Start client (connect to remote FTE server)"
        echo ""
        echo "Example:"
        echo "  # On server machine:"
        echo "  $0 server"
        echo ""
        echo "  # On client machine:"
        echo "  $0 client 192.168.1.100"
        echo "  ssh -p 8079 user@localhost"
        ;;
esac
