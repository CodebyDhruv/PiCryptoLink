#!/usr/bin/env python3
"""
Debug script to verify crypto key derivation and encryption/decryption
"""
import hashlib
import json
import base64
from crypto import AesGcmCipher

def main():
    passphrase = "ecs"  # Same as ESP32
    
    # Show key derivation step by step
    print(f"Passphrase: '{passphrase}'")
    print(f"Passphrase bytes: {passphrase.encode('utf-8')}")
    
    key = hashlib.sha256(passphrase.encode("utf-8")).digest()
    print(f"Derived key (32 bytes): {key.hex().upper()}")
    print(f"Key first 8 bytes: {' '.join(f'{b:02X}' for b in key[:8])}")
    
    # Create cipher and test encryption
    cipher = AesGcmCipher.from_passphrase(passphrase)
    
    test_message = "Hello ESP32!"
    print(f"\nTest message: '{test_message}'")
    
    # Encrypt
    encrypted = cipher.encrypt_to_json(test_message.encode("utf-8"))
    print(f"\nEncrypted JSON:")
    print(json.dumps(encrypted, indent=2))
    
    # Show raw bytes
    iv = base64.b64decode(encrypted["iv"])
    ciphertext = base64.b64decode(encrypted["ciphertext"])
    tag = base64.b64decode(encrypted["tag"])
    
    print(f"\nRaw encrypted data:")
    print(f"IV length: {len(iv)} bytes")
    print(f"IV bytes: {' '.join(f'{b:02X}' for b in iv)}")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"Tag length: {len(tag)} bytes")
    print(f"Tag bytes: {' '.join(f'{b:02X}' for b in tag)}")
    
    # Verify decryption
    try:
        decrypted = cipher.decrypt_from_json(encrypted)
        print(f"\nDecrypted: '{decrypted.decode('utf-8')}'")
        print("✅ Python crypto working correctly")
    except Exception as e:
        print(f"❌ Python decryption failed: {e}")

if __name__ == "__main__":
    main()