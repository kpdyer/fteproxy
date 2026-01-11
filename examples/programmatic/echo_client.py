#!/usr/bin/env python3
"""
FTE-Powered Echo Client

Connects to the FTE echo server and sends a message.
The transmitted data looks like space-separated words to any observer.
"""

import socket
import fteproxy

# Must match the server's formats (but reversed for directions)
CLIENT_TO_SERVER = "^([a-z]+ )+[a-z]+$"
SERVER_TO_CLIENT = "^([A-Z]+ )+[A-Z]+$"

HOST = "127.0.0.1"
PORT = 50007

def main():
    print("FTE Echo Client")
    print("===============")
    print(f"Connecting to {HOST}:{PORT}")
    print()
    
    # Create a regular TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Wrap it with FTE encoding
    sock = fteproxy.wrap_socket(
        sock,
        outgoing_regex=CLIENT_TO_SERVER,
        outgoing_fixed_slice=256,
        incoming_regex=SERVER_TO_CLIENT,
        incoming_fixed_slice=256,
        negotiate=False
    )
    
    sock.connect((HOST, PORT))
    
    # Send a message
    message = b"Hello, FTE World!"
    print(f"Sending: {message.decode()}")
    sock.sendall(message)
    
    # Receive the echo
    data = sock.recv(1024)
    print(f"Received: {data.decode()}")
    
    sock.close()
    print("Done!")


if __name__ == "__main__":
    main()
