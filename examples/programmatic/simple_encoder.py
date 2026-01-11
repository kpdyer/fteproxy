#!/usr/bin/env python3
"""
Simple FTE Encoder Example

This demonstrates direct use of the FTE encoder without network sockets.
Great for understanding how Format-Transforming Encryption works.
"""

import fte

def main():
    # The regex defines what the output looks like
    # This one produces lowercase letters only
    regex = "^[a-z]+$"
    
    # Fixed slice determines the capacity (bits encoded per output character)
    fixed_slice = 256
    
    # Create the encoder
    encoder = fte.Encoder(regex, fixed_slice)
    
    # Our secret message
    plaintext = b"Hello, World! This is a secret message."
    print(f"Original message: {plaintext.decode()}")
    print(f"Original length:  {len(plaintext)} bytes")
    print()
    
    # Encode the message
    ciphertext = encoder.encode(plaintext)
    print(f"Encoded (looks like random letters):")
    print(f"  {ciphertext[:100].decode('ascii', errors='ignore')}...")
    print(f"Encoded length: {len(ciphertext)} bytes")
    print()
    
    # Decode back to original
    decoded, remaining = encoder.decode(ciphertext)
    print(f"Decoded message: {decoded.decode()}")
    print(f"Roundtrip successful: {decoded == plaintext}")


if __name__ == "__main__":
    main()
