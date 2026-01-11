#!/usr/bin/env python3
"""
FTE File Transfer Example

Demonstrates sending a file through FTE encoding.
The file appears as random words to any network observer.
"""

import socket
import sys
import os
import hashlib
import fteproxy

# Formats for file transfer
SENDER_FORMAT = "^([a-z]+ )+[a-z]+$"
RECEIVER_FORMAT = "^([A-Z]+ )+[A-Z]+$"

PORT = 50008
CHUNK_SIZE = 4096


def send_file(filename: str, host: str = "127.0.0.1"):
    """Send a file through FTE encoding."""
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return
    
    # Read file
    with open(filename, "rb") as f:
        data = f.read()
    
    file_hash = hashlib.sha256(data).hexdigest()[:16]
    
    print(f"Sending file: {filename}")
    print(f"Size: {len(data)} bytes")
    print(f"Hash: {file_hash}")
    
    # Create FTE socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = fteproxy.wrap_socket(
        sock,
        outgoing_regex=SENDER_FORMAT,
        outgoing_fixed_slice=256,
        incoming_regex=RECEIVER_FORMAT,
        incoming_fixed_slice=256,
        negotiate=False
    )
    
    sock.connect((host, PORT))
    
    # Send file info first (filename and size)
    basename = os.path.basename(filename)
    info = f"{basename}:{len(data)}:{file_hash}".encode()
    sock.sendall(info + b"\n")
    
    # Send file data
    sock.sendall(data)
    sock.close()
    
    print("File sent successfully!")


def receive_file(save_dir: str = "."):
    """Receive a file through FTE encoding."""
    print(f"Waiting for file on port {PORT}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = fteproxy.wrap_socket(
        sock,
        outgoing_regex=RECEIVER_FORMAT,
        outgoing_fixed_slice=256,
        incoming_regex=SENDER_FORMAT,
        incoming_fixed_slice=256,
        negotiate=False
    )
    
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", PORT))
    sock.listen(1)
    
    conn, addr = sock.accept()
    print(f"Connected from {addr}")
    
    # Receive file info
    info_data = b""
    while b"\n" not in info_data:
        chunk = conn.recv(1024)
        if not chunk:
            break
        info_data += chunk
    
    info_line, remainder = info_data.split(b"\n", 1)
    filename, size_str, expected_hash = info_line.decode().split(":")
    size = int(size_str)
    
    print(f"Receiving: {filename}")
    print(f"Size: {size} bytes")
    
    # Receive file data
    data = remainder
    while len(data) < size:
        chunk = conn.recv(CHUNK_SIZE)
        if not chunk:
            break
        data += chunk
    
    conn.close()
    
    # Verify hash
    actual_hash = hashlib.sha256(data).hexdigest()[:16]
    if actual_hash != expected_hash:
        print(f"Warning: Hash mismatch!")
        print(f"  Expected: {expected_hash}")
        print(f"  Actual:   {actual_hash}")
    
    # Save file
    save_path = os.path.join(save_dir, filename)
    with open(save_path, "wb") as f:
        f.write(data)
    
    print(f"File saved: {save_path}")
    print(f"Hash verified: {actual_hash == expected_hash}")


def main():
    if len(sys.argv) < 2:
        print("FTE File Transfer")
        print("================")
        print()
        print("Usage:")
        print(f"  {sys.argv[0]} receive           - Wait for incoming file")
        print(f"  {sys.argv[0]} send <file> [host] - Send a file")
        print()
        print("Example:")
        print(f"  Terminal 1: {sys.argv[0]} receive")
        print(f"  Terminal 2: {sys.argv[0]} send myfile.txt")
        return
    
    command = sys.argv[1].lower()
    
    if command == "receive":
        receive_file()
    elif command == "send":
        if len(sys.argv) < 3:
            print("Error: Please specify a file to send")
            return
        host = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
        send_file(sys.argv[2], host)
    else:
        print(f"Unknown command: {command}")


if __name__ == "__main__":
    main()
