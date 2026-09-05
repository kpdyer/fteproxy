#!/bin/bash
# SSH over the default HTTP hybrid tunnel.
# Usage: ./ssh_tunnel.sh server | client <connection-uri>

MODE="${1:-help}"
URI="$2"

case "$MODE" in
    server)
        echo "Starting FTE server for SSH tunneling..."
        echo "  FTE listening on wildcard port 8080"
        echo "  Clients may reach: 127.0.0.1:22"
        echo ""
        echo "Make sure sshd is running on port 22."
        echo "Copy the reported connection.txt file privately to the client."
        echo ""
        # --allow is what publishes the local sshd: with no rule at all the
        # server refuses its own loopback addresses.
        python3 -m fteproxy server --allow 127.0.0.1:22
        ;;

    client)
        if [ -z "$URI" ]; then
            echo "Error: pass the URI from the server's connection.txt, e.g."
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
        echo "  # Copy connection.txt privately; set a reachable endpoint with keygen --advertise."
        echo ""
        echo "  # On client machine:"
        echo "  $0 client 'fte://<server-id>@192.168.1.100:8080'"
        echo "  ssh -p 2222 user@localhost"
        ;;
esac
