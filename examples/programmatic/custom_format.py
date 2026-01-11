#!/usr/bin/env python3
"""
Custom FTE Format Example

Shows how to create custom regex formats for specific use cases.
"""

import fte

def demonstrate_format(name: str, regex: str, description: str, secret: bytes):
    """Demonstrate a custom format."""
    print(f"\n{'=' * 60}")
    print(f"Format: {name}")
    print(f"Description: {description}")
    print(f"Regex: {regex}")
    print(f"{'=' * 60}")
    
    try:
        encoder = fte.Encoder(regex, 256)
        ciphertext = encoder.encode(secret)
        
        # Decode for display
        text_output = ciphertext[:256].decode('ascii', errors='ignore')
        print(f"\nEncoded output:")
        print(f"  {text_output[:80]}")
        if len(text_output) > 80:
            print(f"  {text_output[80:160]}")
        
        # Verify
        decoded, _ = encoder.decode(ciphertext)
        print(f"\nDecoded: {decoded.decode()}")
        print(f"✓ Roundtrip successful!")
        
    except Exception as e:
        print(f"✗ Error: {e}")


def main():
    secret = b"Hello, World!"
    
    print("CUSTOM FTE FORMAT EXAMPLES")
    print("==========================")
    print(f"\nSecret message: {secret.decode()}")
    
    # Example 1: Domain names
    demonstrate_format(
        "domain-like",
        "^[a-z0-9]+\\.[a-z]+$",
        "Looks like domain names (e.g., example.com)",
        secret
    )
    
    # Example 2: Email-like
    demonstrate_format(
        "email-like", 
        "^[a-z]+@[a-z]+\\.[a-z]+$",
        "Looks like email addresses",
        b"Hi"  # Smaller data for this format
    )
    
    # Example 3: Key-value pairs
    demonstrate_format(
        "key-value",
        "^[a-z]+=[a-zA-Z0-9]+$",
        "Looks like URL parameters (key=value)",
        b"X"  # Small data
    )
    
    # Example 4: HTTP GET request
    demonstrate_format(
        "http-get",
        "^GET \\/[a-zA-Z0-9]+ HTTP\\/1\\.1\\r\\n\\r\\n$",
        "Looks like HTTP GET requests",
        b"Hi"
    )
    
    # Example 5: JSON-like (simple)
    demonstrate_format(
        "simple-json",
        "^\\{\"[a-z]+\":\"[a-zA-Z0-9]+\"\\}$",
        "Looks like simple JSON objects",
        b"X"
    )
    
    # Example 6: Timestamp-like
    demonstrate_format(
        "timestamp",
        "^[0-9]+:[0-9]+:[0-9]+$",
        "Looks like timestamps (HH:MM:SS)",
        b"X"
    )
    
    print("\n" + "=" * 60)
    print("TIPS FOR CREATING CUSTOM FORMATS:")
    print("=" * 60)
    print("""
1. Simpler regexes work better - avoid complex patterns with many
   length constraints like {min,max}

2. Regexes must start with ^ and end with $

3. Use + for one-or-more repetition instead of specific lengths

4. The more entropy in your alphabet, the more data you can encode
   per character (e.g., [a-zA-Z0-9] > [a-z] > [01])

5. Test your format with small data first to ensure it works
""")


if __name__ == "__main__":
    main()
