import os
import secrets
import hashlib
from Crypto.Cipher import AES  # pip install pycryptodome


# 1. Store a user's password using a slow, salted KDF (scrypt)
def store_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"{salt.hex()}:{key.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        salt_hex, key_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
    except ValueError:
        return False

    actual_key = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return secrets.compare_digest(actual_key, expected_key)


# 2 & 3. Encrypt data using ENC_KEY_HEX and authenticated encryption (AES-256-GCM)
def get_encryption_key() -> bytes:
    key_hex = os.environ.get("ENC_KEY_HEX")
    if not key_hex:
        raise RuntimeError("ENC_KEY_HEX environment variable is not set.")
    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise ValueError("ENC_KEY_HEX must be valid hexadecimal.") from exc
    if len(key) != 32:
        raise ValueError("ENC_KEY_HEX must be 32 bytes (64 hex characters).")
    return key


def encrypt_data(data: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)  # Standard 96-bit GCM nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ciphertext  # 12 bytes + 16 bytes + N bytes


def decrypt_data(blob: bytes, key: bytes) -> bytes:
    if len(blob) < 28:
        raise ValueError("Ciphertext blob is too short to contain nonce and tag.")
    nonce, tag, ciphertext = blob[:12], blob[12:28], blob[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# 4. Make a cryptographically secure, high-entropy password-reset token
def reset_token() -> str:
    return secrets.token_urlsafe(32)


if __name__ == "__main__":
    # Fall back to a generated key only if ENC_KEY_HEX wasn't passed via Docker -e
    if not os.environ.get("ENC_KEY_HEX"):
        os.environ["ENC_KEY_HEX"] = secrets.token_hex(32)

    secret_key = get_encryption_key()

    hashed = store_password("password123")
    print("scrypt:", hashed)
    print("verified:", verify_password("password123", hashed))

    encrypted = encrypt_data(b"A" * 16 + b"A" * 16, secret_key)
    print("gcm:", encrypted.hex())
    print("decrypted:", decrypt_data(encrypted, secret_key))

    print("token:", reset_token())
    