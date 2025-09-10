import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Optional, Tuple

from Crypto.Cipher import AES


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


@dataclass
class AesGcmCipher:
    key: bytes

    @staticmethod
    def from_passphrase(passphrase: str) -> "AesGcmCipher":
        key = hashlib.sha256(passphrase.encode("utf-8")).digest()
        return AesGcmCipher(key=key)

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        iv = os.urandom(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        if aad:
            cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return iv, ciphertext, tag

    def encrypt_to_json(self, plaintext: bytes, aad: Optional[bytes] = None) -> dict:
        iv, ct, tag = self.encrypt(plaintext, aad=aad)
        return {
            "iv": _b64encode(iv),
            "ciphertext": _b64encode(ct),
            "tag": _b64encode(tag),
        }

    def decrypt_from_json(self, payload: dict, aad: Optional[bytes] = None) -> bytes:
        iv = _b64decode(payload["iv"])  # type: ignore[index]
        ct = _b64decode(payload["ciphertext"])  # type: ignore[index]
        tag = _b64decode(payload["tag"])  # type: ignore[index]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        if aad:
            cipher.update(aad)
        return cipher.decrypt_and_verify(ct, tag)