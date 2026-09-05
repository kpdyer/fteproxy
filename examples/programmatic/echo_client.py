#!/usr/bin/env python3
"""Send a small message to the demo echo server using HTTP hybrid mode.

The published server capability matches echo_server.py's private demo key.
"""

import sys
import socket
import fteproxy

# Public capability matching the server script's demo private key.
DEMO_SERVER_ID = "g7RzVlLwycSzfHmHwo2LOdkvZ2rG_-J4lmsosmKPzQY"

# Explicit API format; the API does not infer it from the port.
# Mode defaults to hybrid. See `fteproxy formats` for base names.
FORMAT = "http"

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
