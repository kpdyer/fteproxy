#!/usr/bin/env python3
"""Interactive socket chat using HTTP hybrid mode and a published demo key.

The server binds all IPv4 interfaces on port 50009. Reads display byte-stream
chunks, without application message framing. See examples/integration/README.md.
"""

import socket
import sys
import threading
import fteproxy

# Published demo private key: use a new, private identity for actual deployments.
# The matching public capability is all a client needs to connect.
DEMO_SERVER_KEY = bytes.fromhex(
    "628e1b010509a623c31c54a443d996d10427f2e47ff11258d50e9f70c4b79651")
DEMO_SERVER_ID = fteproxy.server_id(DEMO_SERVER_KEY)

# Explicit HTTP format with the socket API's hybrid mode default.
FORMAT = "http"

PORT = 50009


def receive_messages(conn):
    """Background thread to receive and display messages."""
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                print("\n[Connection closed]")
                break
            print(f"\n>> {data.decode()}")
            print("You: ", end="", flush=True)
        except:
            break


def chat_server():
    """Run as chat server (waits for connection)."""
    print("Secure FTE Chat Server")
    print("=" * 40)
    print(f"Waiting for connection on port {PORT}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = fteproxy.wrap_socket(sock, server_key=DEMO_SERVER_KEY)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", PORT))
    sock.listen(1)
    
    conn, addr = sock.accept()
    print(f"Connected: {addr}")
    print("Type messages and press Enter. Ctrl+C to quit.\n")
    
    # Start receiver thread
    receiver = threading.Thread(target=receive_messages, args=(conn,), daemon=True)
    receiver.start()
    
    try:
        while True:
            msg = input("You: ")
            if msg:
                conn.sendall(msg.encode())
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye!")
    finally:
        conn.close()


def chat_client(host: str):
    """Run as chat client (connects to server)."""
    print("Secure FTE Chat Client")
    print("=" * 40)
    print(f"Connecting to {host}:{PORT}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = fteproxy.wrap_socket(sock, server_id=DEMO_SERVER_ID, format=FORMAT)

    sock.connect((host, PORT))
    print("Connected!")
    print("Type messages and press Enter. Ctrl+C to quit.\n")
    
    # Start receiver thread
    receiver = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    receiver.start()
    
    try:
        while True:
            msg = input("You: ")
            if msg:
                sock.sendall(msg.encode())
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye!")
    finally:
        sock.close()


def main():
    if len(sys.argv) < 2:
        print("Secure FTE Chat")
        print("===============")
        print("\nUsage:")
        print(f"  {sys.argv[0]} server          - Wait for connections")
        print(f"  {sys.argv[0]} client <host>   - Connect to server")
        print("\nExample:")
        print(f"  Terminal 1: {sys.argv[0]} server")
        print(f"  Terminal 2: {sys.argv[0]} client 127.0.0.1")
        return
    
    mode = sys.argv[1].lower()
    
    if mode == "server":
        chat_server()
    elif mode == "client":
        if len(sys.argv) < 3:
            print("Error: Please specify server hostname/IP")
            return
        chat_client(sys.argv[2])
    else:
        print(f"Unknown mode: {mode}")


if __name__ == "__main__":
    main()
