#!/usr/bin/env python3
"""
FTE Chat Client

A simple chat client that has a 10-round conversation with the server.
All traffic is FTE-encoded to look like HTTP/1.1 requests and responses.

The client picks the format and the record-layer mode; the server follows.
All it needs of the server is the server-id below.
"""

import sys
import socket
import fteproxy

# The server-id: the public half of the demo server's keypair, which is all a
# client ever needs. A real client reads this out of a connection string.
DEMO_SERVER_ID = "g7RzVlLwycSzfHmHwo2LOdkvZ2rG_-J4lmsosmKPzQY"

# A base name from the definitions file: the server derives the request and
# response formats from it. `fteproxy formats` lists them all. The demo runs
# on a port no protocol claims, so it takes the shipped default, http.
FORMAT = "http"

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
    print(f"Format: {FORMAT} (HTTP requests out, HTTP responses back)")
    print("=" * 50)
    print()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = fteproxy.wrap_socket(sock, server_id=DEMO_SERVER_ID,
                                    format=FORMAT)
        sock.connect((HOST, PORT))
        print("Connected!")
        print()

        rounds_completed = 0
        
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
                print("Server disconnected unexpectedly")
                return 1

            print(f"  Server: {data.decode()}")
            print()
            rounds_completed += 1

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
