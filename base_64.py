import base64

# Test the exact values from ESP32 output
iv_b64 = "kkjrTX7aSJyu5wsR"
ciphertext_b64 = "lCBaPMg="
tag_b64 = "HfsAK/se3gTZtJeJIOJ8FQ=="

print("Testing base64 decoding:")
print(f"IV: {iv_b64}")
iv_bytes = base64.b64decode(iv_b64)
print(f"IV decoded: {' '.join(f'{b:02X}' for b in iv_bytes)} (length: {len(iv_bytes)})")

print(f"\nCiphertext: {ciphertext_b64}")
ct_bytes = base64.b64decode(ciphertext_b64)
print(f"Ciphertext decoded: {' '.join(f'{b:02X}' for b in ct_bytes)} (length: {len(ct_bytes)})")

print(f"\nTag: {tag_b64}")
tag_bytes = base64.b64decode(tag_b64)
print(f"Tag decoded: {' '.join(f'{b:02X}' for b in tag_bytes)} (length: {len(tag_bytes)})")