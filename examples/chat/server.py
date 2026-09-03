#!/usr/bin/env python3
"""
FTE Chat Server

A simple chat server that has a 10-round conversation with the client.
All traffic is FTE-encoded to look like HTTP/1.1 requests and responses.

The server is told nothing about the format: it learns it, and the
record-layer mode, from the client's first record, and proves its identity
with the private key below.
"""

import sys
import socket
import fteproxy

# A fixed demo identity so the two scripts agree without exchanging anything.
# The private key is published here on purpose: it is a demo. A real server
# generates its own with `fteproxy keygen`, keeps server.key at mode 0600, and
# hands out only the public half.
DEMO_SERVER_KEY = bytes.fromhex(
    "628e1b010509a623c31c54a443d996d10427f2e47ff11258d50e9f70c4b79651")

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
    print("Format and mode: whatever the client asks for")
    print("=" * 50)
    print()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock = fteproxy.wrap_socket(sock, server_key=DEMO_SERVER_KEY)
        sock.bind((HOST, PORT))
        sock.listen(1)

        print("Waiting for client...")
        conn, addr = sock.accept()
        print(f"Client connected from {addr}")
        print()

        rounds_completed = 0
        
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
            rounds_completed += 1

        conn.close()
        sock.close()
        print("Chat ended.")
        
        if rounds_completed == 10:
            print("[OK] All 10 rounds completed successfully")
            return 0
        else:
            print(f"[FAIL] Only {rounds_completed}/10 rounds completed")
            return 1
            
    except Exception as e:
        print(f"[ERROR] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
