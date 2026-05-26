"""AES encryption utilities for sensitive data (SSH passwords, keys)."""

import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# 32-byte key from env (generate once, keep secret)
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
KEY = SECRET_KEY.encode().ljust(32, b"\x00")[:32]


def encrypt(plaintext: str) -> str:
    """Encrypt a string, return base64-encoded ciphertext with IV prepended."""
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), 16))
    return base64.b64encode(iv + ct).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a base64-encoded string (IV + ciphertext)."""
    raw = base64.b64decode(ciphertext)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), 16)
    return pt.decode()


def mask_password(pw: str) -> str:
    """Show only first 2 and last 2 chars for display."""
    if len(pw) <= 4:
        return "****"
    return pw[:2] + "*" * (len(pw) - 4) + pw[-2:]
