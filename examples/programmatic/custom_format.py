#!/usr/bin/env python3
"""
Custom Format Example

Shows how to create your own regex format for FTE encoding.
"""

import sys
import fte


def main():
    print("=" * 60)
    print("CUSTOM FORMAT EXAMPLE")
    print("=" * 60)
    
    errors = 0
    
    # Example 1: DNA sequences
    print("\n[1] DNA Sequence Format")
    print("    Regex: ^[ACGT]+$")
    dna_regex = "^[ACGT]+$"
    try:
        encoder = fte.Encoder(dna_regex, 256)
        plaintext = b"Secret genetic data"
        ciphertext = encoder.encode(plaintext)
        decoded, _ = encoder.decode(ciphertext)
        print(f"    Input:  {plaintext.decode()}")
        print(f"    Output: {ciphertext[:50].decode('ascii', errors='ignore')}...")
        if decoded == plaintext:
            print("    [OK] Roundtrip verified")
        else:
            print("    [FAIL] Roundtrip failed")
            errors += 1
    except Exception as e:
        print(f"    [ERROR] {e}")
        errors += 1
    
    # Example 2: Emoji-like (using simple chars that look like patterns)
    print("\n[2] Simple Pattern Format")
    print("    Regex: ^[ox]+$")
    pattern_regex = "^[ox]+$"
    try:
        encoder = fte.Encoder(pattern_regex, 256)
        plaintext = b"Hidden message"
        ciphertext = encoder.encode(plaintext)
        decoded, _ = encoder.decode(ciphertext)
        print(f"    Input:  {plaintext.decode()}")
        print(f"    Output: {ciphertext[:50].decode('ascii', errors='ignore')}...")
        if decoded == plaintext:
            print("    [OK] Roundtrip verified")
        else:
            print("    [FAIL] Roundtrip failed")
            errors += 1
    except Exception as e:
        print(f"    [ERROR] {e}")
        errors += 1
    
    # Example 3: File extension-like
    print("\n[3] Filename Format")
    print("    Regex: ^[a-z]+\\.[a-z]{3}$")
    filename_regex = "^[a-z]+\\.[a-z]{3}$"
    try:
        encoder = fte.Encoder(filename_regex, 64)
        plaintext = b"Hi"
        ciphertext = encoder.encode(plaintext)
        decoded, _ = encoder.decode(ciphertext)
        print(f"    Input:  {plaintext.decode()}")
        print(f"    Output: {ciphertext[:50].decode('ascii', errors='ignore')}...")
        if decoded == plaintext:
            print("    [OK] Roundtrip verified")
        else:
            print("    [FAIL] Roundtrip failed")
            errors += 1
    except Exception as e:
        print(f"    [ERROR] {e}")
        errors += 1
    
    # Example 4: MAC address-like
    print("\n[4] Hex Pairs Format")
    print("    Regex: ^[0-9a-f][0-9a-f]+$")
    mac_regex = "^[0-9a-f][0-9a-f]+$"
    try:
        encoder = fte.Encoder(mac_regex, 256)
        plaintext = b"Network data"
        ciphertext = encoder.encode(plaintext)
        decoded, _ = encoder.decode(ciphertext)
        print(f"    Input:  {plaintext.decode()}")
        print(f"    Output: {ciphertext[:50].decode('ascii', errors='ignore')}...")
        if decoded == plaintext:
            print("    [OK] Roundtrip verified")
        else:
            print("    [FAIL] Roundtrip failed")
            errors += 1
    except Exception as e:
        print(f"    [ERROR] {e}")
        errors += 1
    
    print("\n" + "=" * 60)
    
    if errors > 0:
        print(f"[FAIL] {errors} format(s) had errors")
        return 1
    
    print("[OK] All custom formats work successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
