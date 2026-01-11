#!/usr/bin/env python3
"""
HTTP Format Demo

Shows data encoded to look like HTTP requests.
Useful for blending in with normal web traffic.
"""

import sys
import fte


def main():
    # HTTP GET request format
    regex = "^GET \\/[a-zA-Z0-9]+ HTTP\\/1\\.1\\r\\n\\r\\n$"
    fixed_slice = 256
    errors = 0
    
    encoder = fte.Encoder(regex, fixed_slice)
    
    print("=" * 60)
    print("HTTP FORMAT DEMO")
    print("Traffic looks like HTTP GET requests")
    print("=" * 60)
    
    messages = [b"Hi", b"Test", b"Secret"]
    
    for msg in messages:
        try:
            ciphertext = encoder.encode(msg)
            http_output = ciphertext[:256].decode('ascii', errors='ignore')
            
            print(f"\nOriginal: {msg}")
            print(f"Encoded (HTTP-like):")
            for line in http_output.split('\r\n'):
                print(f"    {repr(line)}")
            
            # Verify
            decoded, _ = encoder.decode(ciphertext)
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
