#!/usr/bin/env python3
"""Echo bytes through a wrapped TCP socket using a published demo identity.

Accept the client's format/mode from the configured definitions release.
The companion client uses HTTP hybrid mode on port 50007.
"""

import sys
import socket
import fteproxy

# Published demo private key: use a new, private identity for actual deployments.
# The matching public capability is all a client needs to connect.
DEMO_SERVER_KEY = bytes.fromhex(
    "628e1b010509a623c31c54a443d996d10427f2e47ff11258d50e9f70c4b79651")

HOST = ""          # All interfaces
PORT = 50007       # Arbitrary port


def main():
    print("FTE Echo Server")
    print("===============")
    print(f"Listening on port {PORT}")
    print("Format and mode: selected by the client from this definitions release")
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
