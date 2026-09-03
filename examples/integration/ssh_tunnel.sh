#!/bin/bash
# SSH Tunnel Over FTE
#
# This script sets up an SSH tunnel through fteproxy.
# Traffic will appear as HTTP-like patterns to network observers.
#
# Usage:
#   Server: ./ssh_tunnel.sh server
#   Client: ./ssh_tunnel.sh client <connection-string>

MODE="${1:-help}"
URI="$2"

case "$MODE" in
    server)
        echo "Starting FTE server for SSH tunneling..."
        echo "  FTE listening on: 0.0.0.0:8080"
        echo "  Clients may reach: 127.0.0.1:22"
        echo ""
        echo "Make sure sshd is running on port 22."
        echo "Hand a client the connection string printed below."
        echo ""
        # --allow is what publishes the local sshd: with no rule at all the
        # server refuses its own loopback addresses.
        python3 -m fteproxy server --allow 127.0.0.1:22
        ;;

    client)
        if [ -z "$URI" ]; then
            echo "Error: pass the connection string the server printed, e.g."
            echo "  $0 client 'fte://<server-id>@192.168.1.100:8080'"
            exit 2
        fi
        echo "Starting FTE client for SSH tunneling..."
        echo "  Local port: 2222 -> 127.0.0.1:22 through the tunnel"
        echo ""
        echo "To connect via SSH, run:"
        echo "  ssh -p 2222 user@localhost"
        echo ""
        python3 -m fteproxy client "$URI" -L 2222:127.0.0.1:22
        ;;

    *)
        echo "SSH Tunnel Over FTE"
        echo "==================="
        echo ""
        echo "Usage:"
        echo "  $0 server                      - Start server (publishes local SSH)"
        echo "  $0 client <connection-string>  - Start client (connect to remote FTE server)"
        echo ""
        echo "Example:"
        echo "  # On server machine:"
        echo "  $0 server"
        echo "  # It prints a connection string; copy it to the client."
        echo ""
        echo "  # On client machine:"
        echo "  $0 client 'fte://<server-id>@192.168.1.100:8080'"
        echo "  ssh -p 2222 user@localhost"
        ;;
esac
