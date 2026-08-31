#!/usr/bin/env python3
"""
Simple FTE Encoder Example

This demonstrates direct use of the FTE cipher without network sockets.
Great for understanding how Format-Transforming Encryption works.
"""

import os
import sys
import fte


def main():
    # The regex defines what the output looks like
    # This one produces lowercase letters only
    regex = "^[a-z]+$"

    # Fixed slice determines the capacity (bits encoded per output character)
    fixed_slice = 256

    # libfte 0.4 requires an explicit 32-byte key (there is no random-key path)
    key = os.urandom(32)

    # Create the cipher
    cipher = fte.FTE(output_format=fte.RegexFormat(regex, length=fixed_slice), key=key)
    
    # Our secret message
    plaintext = b"Hello, World! This is a secret message."
    print(f"Original message: {plaintext.decode()}")
    print(f"Original length:  {len(plaintext)} bytes")
    print()
    
    # Encode the message
    ciphertext = cipher.encrypt(plaintext)
    print(f"Encoded (looks like random letters):")
    print(f"  {ciphertext[:100].decode('ascii', errors='ignore')}...")
    print(f"Encoded length: {len(ciphertext)} bytes")
    print()
    
    # Decode back to original
    decoded = cipher.decrypt(ciphertext)
    print(f"Decoded message: {decoded.decode()}")
    
    # Verify roundtrip
    success = decoded == plaintext
    print(f"Roundtrip successful: {success}")
    
    if not success:
        print("[FAIL] Roundtrip verification failed!")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
