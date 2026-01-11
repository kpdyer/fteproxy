#!/usr/bin/env python3
"""
FTE Format Demonstration

Shows how the same data looks when encoded with different regex formats.
"""

import sys
import fte

# Available formats with their regex patterns
FORMATS = {
    "lowercase": ("^[a-z]+$", "Random lowercase letters"),
    "uppercase": ("^[A-Z]+$", "Random UPPERCASE letters"),
    "digits": ("^[0-9]+$", "Random digits"),
    "hex": ("^[0-9a-f]+$", "Hexadecimal string"),
    "alphanumeric": ("^[a-zA-Z0-9]+$", "Mixed letters and numbers"),
    "words": ("^([a-z]+ )+[a-z]+$", "Space-separated words"),
    "binary": ("^[01]+$", "Binary string (0s and 1s)"),
    "base64": ("^[a-zA-Z0-9+/]+$", "Base64-like characters"),
    "url_path": ("^\\/[a-z0-9]+(\\/[a-z0-9]+)*$", "URL path-like"),
    "csv": ("^[a-zA-Z0-9]+(,[a-zA-Z0-9]+)+$", "Comma-separated values"),
}


def main():
    secret = b"Secret Message!"
    fixed_slice = 256
    errors = 0
    
    print("=" * 70)
    print("FTE FORMAT DEMONSTRATION")
    print("=" * 70)
    print(f"\nOriginal data: {secret.decode()}")
    print(f"Original length: {len(secret)} bytes")
    print("\n" + "-" * 70)
    
    for name, (regex, description) in FORMATS.items():
        print(f"\nFormat: {name}")
        print(f"   Description: {description}")
        print(f"   Regex: {regex}")
        
        try:
            encoder = fte.Encoder(regex, fixed_slice)
            ciphertext = encoder.encode(secret)
            
            # Show first 60 chars of output
            preview = ciphertext[:60].decode('ascii', errors='ignore')
            print(f"   Output: {preview}...")
            print(f"   Length: {len(ciphertext)} bytes")
            
            # Verify roundtrip
            decoded, _ = encoder.decode(ciphertext)
            if decoded != secret:
                print(f"   [FAIL] Roundtrip failed!")
                errors += 1
            else:
                print(f"   [OK] Roundtrip verified")
            
        except Exception as e:
            print(f"   [ERROR] {e}")
            errors += 1
        
        print("-" * 70)
    
    if errors > 0:
        print(f"\n[FAIL] {errors} format(s) had errors")
        return 1
    
    print("\n[OK] All formats verified successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
