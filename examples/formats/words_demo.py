#!/usr/bin/env python3
"""
Words Format Demo

Shows data encoded as space-separated lowercase words.
This is useful when you want traffic to look like natural text.
"""

import fte

def main():
    # The words format: space-separated lowercase words
    regex = "^([a-z]+ )+[a-z]+$"
    fixed_slice = 256
    
    encoder = fte.Encoder(regex, fixed_slice)
    
    messages = [
        b"Hello!",
        b"Secret message",
        b"Binary data: \x00\x01\x02",
        b"The quick brown fox",
    ]
    
    print("=" * 60)
    print("WORDS FORMAT DEMO")
    print("Traffic looks like natural language words")
    print("=" * 60)
    
    for msg in messages:
        ciphertext = encoder.encode(msg)
        words = ciphertext[:256].decode('ascii', errors='ignore')
        
        print(f"\nOriginal: {msg}")
        print(f"Encoded:  {words[:70]}...")
        
        # Count words
        word_count = len(words.split())
        print(f"Words:    {word_count} words generated")
        
        # Verify roundtrip
        decoded, _ = encoder.decode(ciphertext)
        assert decoded == msg
        print("[OK] Roundtrip verified")


if __name__ == "__main__":
    main()
