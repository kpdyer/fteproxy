#!/usr/bin/env python3
"""
FTE-Powered Echo Client

Connects to the FTE echo server and sends a message.
The transmitted data looks like space-separated words to any observer.

The client picks the format; the server follows. All it needs of the server
is the server-id below.
"""

import sys
import socket
import fteproxy

# The server-id: the public half of the demo server's keypair, which is all a
# client ever needs. A real client reads this out of a connection string.
DEMO_SERVER_ID = "g7RzVlLwycSzfHmHwo2LOdkvZ2rG_-J4lmsosmKPzQY"

# A base name from the definitions file. `fteproxy formats` lists them all.
FORMAT = "words"

HOST = "127.0.0.1"
PORT = 50007


def main():
    print("FTE Echo Client")
    print("===============")
    print(f"Connecting to {HOST}:{PORT}")
    print()
    
    try:
        # Create a regular TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Wrap it with FTE encoding, in the client role
        sock = fteproxy.wrap_socket(sock, server_id=DEMO_SERVER_ID,
                                    format=FORMAT)
        
        sock.connect((HOST, PORT))
        
        # Send a message
        message = b"Hello, FTE World!"
        print(f"Sending: {message.decode()}")
        sock.sendall(message)
        
        # Receive the echo
        data = sock.recv(1024)
        print(f"Received: {data.decode()}")
        
        sock.close()
        
        # Verify echo worked
        if data == message:
            print("[OK] Echo successful - received matches sent")
            return 0
        else:
            print(f"[FAIL] Echo mismatch: expected {message}, got {data}")
            return 1
            
    except Exception as e:
        print(f"[ERROR] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
