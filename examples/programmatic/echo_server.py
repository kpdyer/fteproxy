#!/usr/bin/env python3
"""
FTE-Powered Echo Server

Listens for FTE-encoded connections and echoes back any received data.
The transmitted data looks like space-separated words to any observer.

The server is told no format at all: it learns the format and the
record-layer mode from the client's first record.
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

HOST = ""          # All interfaces
PORT = 50007       # Arbitrary port


def main():
    print("FTE Echo Server")
    print("===============")
    print(f"Listening on port {PORT}")
    print("Format and mode: whatever the client asks for")
    print()
    
    try:
        # Create a regular TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Wrap it with FTE encoding, in the server role
        sock = fteproxy.wrap_socket(sock, server_key=DEMO_SERVER_KEY)
        
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
