#!/usr/bin/env python3
"""
Format Comparison Demo

Encodes the same message with multiple formats side-by-side
to show how different formats transform the same data.
"""

import fte

FORMATS = [
    ("Lowercase", "^[a-z]+$"),
    ("Uppercase", "^[A-Z]+$"),
    ("Digits", "^[0-9]+$"),
    ("Hex", "^[0-9a-f]+$"),
    ("Words", "^([a-z]+ )+[a-z]+$"),
    ("Binary", "^[01]+$"),
    ("Base64", "^[a-zA-Z0-9+/]+$"),
    ("URL Path", "^\\/[a-z0-9]+(\\/[a-z0-9]+)*$"),
    ("CSV", "^[a-zA-Z0-9]+(,[a-zA-Z0-9]+)+$"),
]

def main():
    secret = b"Hello, World!"
    
    print("=" * 70)
    print("FORMAT COMPARISON")
    print("=" * 70)
    print(f"\nSecret message: {secret.decode()}")
    print(f"Length: {len(secret)} bytes\n")
    
    print("-" * 70)
    print(f"{'Format':<12} | {'Sample Output':<55}")
    print("-" * 70)
    
    for name, regex in FORMATS:
        try:
            encoder = fte.Encoder(regex, 256)
            ciphertext = encoder.encode(secret)
            sample = ciphertext[:55].decode('ascii', errors='ignore')
            
            # Verify it decodes correctly
            decoded, _ = encoder.decode(ciphertext)
            status = "[OK]" if decoded == secret else "[FAIL]"
            
            print(f"{name:<12} | {sample}")
        except Exception as e:
            print(f"{name:<12} | Error: {str(e)[:45]}")
    
    print("-" * 70)
    
    print("""
Observations:
- All formats encode the same data differently
- Simpler alphabets (like binary) need more characters
- Larger alphabets (like base64) are more compact
- Each format has its own use case for blending in
""")


if __name__ == "__main__":
    main()
