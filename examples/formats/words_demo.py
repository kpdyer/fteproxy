#!/usr/bin/env python3
"""Encode local messages as space-separated lowercase letter sequences.

The regex does not generate natural language. See README.md for the long
prefixes produced by short, unpadded libfte plaintexts.
"""

import os
import sys
import fte


def main():
    # The words format: space-separated lowercase words
    regex = "^([a-z]+ )+[a-z]+$"
    length = 256
    errors = 0

    # libfte 0.4 requires an explicit 32-byte key
    key = os.urandom(32)
    cipher = fte.FTE(output_format=fte.RegexFormat(regex, length=length), key=key)
    
    messages = [
        b"Hello!",
        b"Secret message",
        b"Binary data: \x00\x01\x02",
        b"The quick brown fox",
    ]
    
    print("=" * 60)
    print("WORDS FORMAT DEMO")
    print("Output is space-separated lowercase letter sequences")
    print("=" * 60)
    
    for msg in messages:
        ciphertext = cipher.encrypt(msg)
        words = ciphertext[:256].decode('ascii', errors='ignore')
        
        print(f"\nOriginal: {msg}")
        print(f"Encoded:  {words[:70]}...")
        
        # Count words
        word_count = len(words.split())
        print(f"Words:    {word_count} words generated")
        
        # Verify roundtrip
        decoded = cipher.decrypt(ciphertext)
        if decoded == msg:
            print("[OK] Roundtrip verified")
        else:
            print("[FAIL] Roundtrip failed!")
            errors += 1
    
    print()
    if errors > 0:
        print(f"[FAIL] {errors} message(s) failed roundtrip")
        return 1
    
    print("[OK] All messages verified successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
