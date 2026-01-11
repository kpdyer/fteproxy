#!/usr/bin/env python3
"""
FTE File Transfer Example

Demonstrates sending a file through FTE encoding.
The file appears as random words to any network observer.

Run without arguments to execute a self-test.
"""

import socket
import sys
import os
import hashlib
import threading
import tempfile
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
        return False
    
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
    return True


def receive_file(save_dir: str = "."):
    """Receive a file through FTE encoding. Returns (success, saved_path)."""
    print(f"Waiting for file on port {PORT}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock = fteproxy.wrap_socket(
        sock,
        outgoing_regex=RECEIVER_FORMAT,
        outgoing_fixed_slice=256,
        incoming_regex=SENDER_FORMAT,
        incoming_fixed_slice=256,
        negotiate=False
    )
    
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
    sock.close()
    
    # Verify hash
    actual_hash = hashlib.sha256(data).hexdigest()[:16]
    hash_ok = actual_hash == expected_hash
    
    if not hash_ok:
        print(f"Warning: Hash mismatch!")
        print(f"  Expected: {expected_hash}")
        print(f"  Actual:   {actual_hash}")
    
    # Save file
    save_path = os.path.join(save_dir, filename)
    with open(save_path, "wb") as f:
        f.write(data)
    
    print(f"File saved: {save_path}")
    print(f"Hash verified: {hash_ok}")
    
    return hash_ok, save_path


def run_self_test():
    """Run a self-test that sends and receives a file."""
    print("=" * 50)
    print("FTE File Transfer Self-Test")
    print("=" * 50)
    print()
    
    # Create a temp file with test data
    test_content = b"This is a test file for FTE file transfer.\n" * 100
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file
        test_file = os.path.join(tmpdir, "test_input.txt")
        with open(test_file, "wb") as f:
            f.write(test_content)
        
        original_hash = hashlib.sha256(test_content).hexdigest()
        print(f"Created test file: {len(test_content)} bytes")
        print(f"Original hash: {original_hash[:16]}")
        print()
        
        # Start receiver in a thread
        received_result = [None, None]  # [success, path]
        
        def receiver_thread():
            try:
                received_result[0], received_result[1] = receive_file(tmpdir)
            except Exception as e:
                print(f"Receiver error: {e}")
                received_result[0] = False
        
        receiver = threading.Thread(target=receiver_thread)
        receiver.start()
        
        # Give receiver time to start
        import time
        time.sleep(1)
        
        # Send the file
        print()
        send_success = send_file(test_file)
        
        # Wait for receiver to finish
        receiver.join(timeout=30)
        
        print()
        print("=" * 50)
        
        # Verify results
        if not send_success:
            print("[FAIL] Send failed")
            return 1
        
        if not received_result[0]:
            print("[FAIL] Receive failed or hash mismatch")
            return 1
        
        # Verify received content
        with open(received_result[1], "rb") as f:
            received_content = f.read()
        
        if received_content == test_content:
            print("[OK] File transfer successful - content verified")
            return 0
        else:
            print("[FAIL] Received content does not match original")
            return 1


def main():
    if len(sys.argv) < 2:
        # Run self-test when no arguments
        return run_self_test()
    
    command = sys.argv[1].lower()
    
    if command == "test":
        return run_self_test()
    elif command == "receive":
        success, _ = receive_file()
        return 0 if success else 1
    elif command == "send":
        if len(sys.argv) < 3:
            print("Error: Please specify a file to send")
            return 1
        host = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
        success = send_file(sys.argv[2], host)
        return 0 if success else 1
    elif command == "help" or command == "--help":
        print("FTE File Transfer")
        print("================")
        print()
        print("Usage:")
        print(f"  {sys.argv[0]}                   - Run self-test")
        print(f"  {sys.argv[0]} test              - Run self-test")
        print(f"  {sys.argv[0]} receive           - Wait for incoming file")
        print(f"  {sys.argv[0]} send <file> [host] - Send a file")
        print()
        print("Example:")
        print(f"  Terminal 1: {sys.argv[0]} receive")
        print(f"  Terminal 2: {sys.argv[0]} send myfile.txt")
        return 0
    else:
        print(f"Unknown command: {command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
