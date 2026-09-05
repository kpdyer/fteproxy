#!/usr/bin/env python3
"""
Custom Format Example

Shows how to create your own regex format for FTE encoding.
"""

import os
import sys
import fte


def main():
    print("=" * 60)
    print("CUSTOM FORMAT EXAMPLE")
    print("=" * 60)

    # libfte 0.4 requires an explicit 32-byte key; one key for the whole script is fine
    key = os.urandom(32)

    errors = 0
    
    # Example 1: DNA sequences
    print("\n[1] DNA Sequence Format")
    print("    Regex: ^[ACGT]+$")
    dna_regex = "^[ACGT]+$"
    try:
        cipher = fte.FTE(output_format=fte.RegexFormat(dna_regex, length=512), key=key)
        plaintext = b"Secret genetic data"
        ciphertext = cipher.encrypt(plaintext)
        decoded = cipher.decrypt(ciphertext)
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
    
    # Example 2: a two-symbol alphabet.
    print("\n[2] Simple Pattern Format")
    print("    Regex: ^[ox]+$")
    pattern_regex = "^[ox]+$"
    try:
        cipher = fte.FTE(output_format=fte.RegexFormat(pattern_regex, length=1024), key=key)
        plaintext = b"Hidden message"
        ciphertext = cipher.encrypt(plaintext)
        decoded = cipher.decrypt(ciphertext)
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
    print("    Regex: ^[a-z]+\\.[a-z][a-z][a-z]$")
    filename_regex = "^[a-z]+\\.[a-z][a-z][a-z]$"
    try:
        cipher = fte.FTE(output_format=fte.RegexFormat(filename_regex, length=256), key=key)
        plaintext = b"Hi"
        ciphertext = cipher.encrypt(plaintext)
        decoded = cipher.decrypt(ciphertext)
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
    
    # Example 4: a hex string of at least two characters.
    print("\n[4] Hex String Format")
    print("    Regex: ^[0-9a-f][0-9a-f]+$")
    mac_regex = "^[0-9a-f][0-9a-f]+$"
    try:
        cipher = fte.FTE(output_format=fte.RegexFormat(mac_regex, length=256), key=key)
        plaintext = b"Network data"
        ciphertext = cipher.encrypt(plaintext)
        decoded = cipher.decrypt(ciphertext)
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
