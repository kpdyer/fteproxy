#!/usr/bin/env python3
"""
FTE-Powered Echo Server

Listens for FTE-encoded connections and echoes back any received data.
The transmitted data looks like space-separated words to any observer.
"""

import sys
import socket
import fteproxy

# Define the regex formats for each direction
# Client->Server: looks like lowercase words
CLIENT_TO_SERVER = "^([a-z]+ )+[a-z]+$"
# Server->Client: looks like UPPERCASE words  
SERVER_TO_CLIENT = "^([A-Z]+ )+[A-Z]+$"

HOST = ""          # All interfaces
PORT = 50007       # Arbitrary port


def main():
    print("FTE Echo Server")
    print("===============")
    print(f"Listening on port {PORT}")
    print(f"Client->Server format: words (lowercase)")
    print(f"Server->Client format: WORDS (UPPERCASE)")
    print()
    
    try:
        # Create a regular TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Wrap it with FTE encoding
        sock = fteproxy.wrap_socket(
            sock,
            outgoing_regex=SERVER_TO_CLIENT,
            outgoing_fixed_slice=256,
            incoming_regex=CLIENT_TO_SERVER,
            incoming_fixed_slice=256,
            negotiate=False  # Both sides know the formats
        )
        
        sock.bind((HOST, PORT))
        sock.listen(1)
        
        print("Waiting for connection...")
        conn, addr = sock.accept()
        print(f"Connected by {addr}")
        
        messages_echoed = 0
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"Received: {data.decode()}")
            conn.sendall(data)  # Echo back
            print(f"Echoed back: {data.decode()}")
            messages_echoed += 1
        
        conn.close()
        sock.close()
        print("Connection closed")
        
        if messages_echoed > 0:
            print(f"[OK] Echoed {messages_echoed} message(s) successfully")
            return 0
        else:
            print("[FAIL] No messages were echoed")
            return 1
            
    except Exception as e:
        print(f"[ERROR] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
