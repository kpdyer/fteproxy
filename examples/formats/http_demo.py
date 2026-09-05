#!/usr/bin/env python3
"""Encode local messages as a simplified HTTP-like GET shape with libfte.

This example omits the HTTP/1.1 Host header. It does not use the proxy's
current HTTP definitions or its padded session records.
"""

import os
import sys
import fte


def main():
    # HTTP GET request format
    regex = "^GET \\/[a-zA-Z0-9]+ HTTP\\/1\\.1\\r\\n\\r\\n$"
    length = 256
    errors = 0

    # libfte 0.4 requires an explicit 32-byte key
    key = os.urandom(32)
    cipher = fte.FTE(output_format=fte.RegexFormat(regex, length=length), key=key)
    
    print("=" * 60)
    print("HTTP FORMAT DEMO")
    print("Output uses a simplified HTTP-like GET shape")
    print("=" * 60)
    
    messages = [b"Hi", b"Test", b"Secret"]
    
    for msg in messages:
        try:
            ciphertext = cipher.encrypt(msg)
            http_output = ciphertext[:256].decode('ascii', errors='ignore')
            
            print(f"\nOriginal: {msg}")
            print(f"Encoded (HTTP-like):")
            for line in http_output.split('\r\n'):
                print(f"    {repr(line)}")
            
            # Verify
            decoded = cipher.decrypt(ciphertext)
            if decoded == msg:
                print("[OK] Roundtrip verified")
            else:
                print("[FAIL] Roundtrip failed!")
                errors += 1
        except Exception as e:
            print(f"[ERROR] {e}")
            errors += 1
    
    print()
    if errors > 0:
        print(f"[FAIL] {errors} message(s) failed")
        return 1
    
    print("[OK] All HTTP format tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
