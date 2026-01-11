#!/usr/bin/env python3
"""
FTE Chat Client

A simple chat client that has a 10-round conversation with the server.
All traffic is FTE-encoded to look like binary (0s and 1s) or letters (As and Bs).
"""

import socket
import fteproxy

# Format definitions - must match server
CLIENT_TO_SERVER = '^(0|1)+$'   # Client sends as binary
SERVER_TO_CLIENT = '^(A|B)+$'   # Server sends as A/B letters

HOST = '127.0.0.1'
PORT = 50007

# Client's messages for each round
MESSAGES = [
    b"Hi there! How are you?",
    b"What does FTE stand for?",
    b"How does it work?",
    b"What does my traffic look like right now?",
    b"And what about your responses?",
    b"That's amazing!",
    b"Where can I learn more?",
    b"Can I customize the output format?",
    b"This has been very informative!",
    b"Bye! Thanks for the chat!",
]


def main():
    print("FTE Chat Client")
    print("=" * 50)
    print(f"Connecting to {HOST}:{PORT}")
    print(f"Client->Server format: binary (0s and 1s)")
    print(f"Server->Client format: letters (As and Bs)")
    print("=" * 50)
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = fteproxy.wrap_socket(sock,
                                outgoing_regex=CLIENT_TO_SERVER,
                                outgoing_fixed_slice=256,
                                incoming_regex=SERVER_TO_CLIENT,
                                incoming_fixed_slice=256,
                                negotiate=False)
    sock.connect((HOST, PORT))
    print("Connected!")
    print()

    # 10-round conversation
    for round_num in range(10):
        # Send message to server
        message = MESSAGES[round_num]
        sock.sendall(message)

        print(f"[Round {round_num + 1}/10]")
        print(f"  Client: {message.decode()}")

        # Receive response
        data = sock.recv(4096)
        if not data:
            print("Server disconnected")
            break

        print(f"  Server: {data.decode()}")
        print()

    sock.close()
    print("Chat ended.")


if __name__ == "__main__":
    main()
