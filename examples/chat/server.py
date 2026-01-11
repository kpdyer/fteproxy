#!/usr/bin/env python3
"""
FTE Chat Server

A simple chat server that has a 10-round conversation with the client.
All traffic is FTE-encoded to look like binary (0s and 1s) or letters (As and Bs).
"""

import socket
import fteproxy

# Format definitions - must match client
CLIENT_TO_SERVER = '^(0|1)+$'   # Client sends as binary
SERVER_TO_CLIENT = '^(A|B)+$'   # Server sends as A/B letters

HOST = ''       # All interfaces
PORT = 50007

# Server's responses for each round
RESPONSES = [
    b"Hello! Welcome to the FTE chat server.",
    b"I'm doing great, thanks for asking!",
    b"FTE stands for Format-Transforming Encryption.",
    b"It encodes data to match regular expressions.",
    b"Right now, your messages look like: 010110101...",
    b"And my messages look like: ABBAABABBA...",
    b"Pretty cool for evading traffic analysis!",
    b"The paper was published at CCS 2013.",
    b"You can define custom formats too.",
    b"Goodbye! Thanks for chatting with FTE!",
]


def main():
    print("FTE Chat Server")
    print("=" * 50)
    print(f"Listening on port {PORT}")
    print(f"Client->Server format: binary (0s and 1s)")
    print(f"Server->Client format: letters (As and Bs)")
    print("=" * 50)
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock = fteproxy.wrap_socket(sock,
                                outgoing_regex=SERVER_TO_CLIENT,
                                outgoing_fixed_slice=256,
                                incoming_regex=CLIENT_TO_SERVER,
                                incoming_fixed_slice=256,
                                negotiate=False)
    sock.bind((HOST, PORT))
    sock.listen(1)

    print("Waiting for client...")
    conn, addr = sock.accept()
    print(f"Client connected from {addr}")
    print()

    # 10-round conversation
    for round_num in range(10):
        # Receive message from client
        data = conn.recv(4096)
        if not data:
            print("Client disconnected")
            break

        print(f"[Round {round_num + 1}/10]")
        print(f"  Client: {data.decode()}")

        # Send response
        response = RESPONSES[round_num]
        conn.sendall(response)
        print(f"  Server: {response.decode()}")
        print()

    conn.close()
    sock.close()
    print("Chat ended.")


if __name__ == "__main__":
    main()
