#!/usr/bin/env python3
"""Serve a scripted ten-round conversation using a published demo identity.

The client selects format/mode from this server's definitions release.
The companion client uses HTTP hybrid mode. See examples/chat/README.md.
"""

import sys
import socket
import fteproxy

# Published demo private key: use a new, private identity for actual deployments.
# The matching public capability is all a client needs to connect.
DEMO_SERVER_KEY = bytes.fromhex(
    "628e1b010509a623c31c54a443d996d10427f2e47ff11258d50e9f70c4b79651")

HOST = ''       # All interfaces
PORT = 50007

# Server's responses for each round
RESPONSES = [
    b"Hello! Ready to demonstrate the FTE tunnel.",
    b"FTE stands for Format-Transforming Encryption.",
    b"It encrypts data and encodes covertexts to match regular expressions.",
    b"This demo uses HTTP POST headers and encrypted chunked bodies.",
    b"My responses also use HTTP headers and encrypted chunked bodies.",
    b"The message shape alone does not prevent traffic analysis.",
    b"The repository README and format-authoring guide explain the details.",
    b"Yes. Add matching request and response definitions on both peers.",
    b"Try format mode to encode the payload into covertexts too.",
    b"Goodbye! Thanks for trying the demo.",
]


def main():
    print("FTE Chat Server")
    print("=" * 50)
    print(f"Listening on port {PORT}")
    print("Format and mode: selected by the client from this definitions release")
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
