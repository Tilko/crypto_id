

from __future__ import annotations

import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"PQE1"  # format marker
VERSION = 1

# Scrypt params (adjust to your machine; these are reasonable starting points)
SCRYPT_N = 2**18   # CPU/memory cost (must be power of 2)
SCRYPT_R = 8
SCRYPT_P = 1

SALT_LEN = 16
NONCE_LEN = 12     # AES-GCM standard
KEY_LEN = 32       # 256-bit


def _derive_key(password: str, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(in_path: str | Path, out_path: str | Path, password: str) -> None:
    in_path = Path(in_path)
    out_path = Path(out_path)

    plaintext = in_path.read_bytes()

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)

    aead = AESGCM(key)
    ciphertext = aead.encrypt(nonce, plaintext, associated_data=None)

    # Header: MAGIC(4) | ver(u8) | n(u32) r(u32) p(u32) | salt(16) | nonce(12) | ciphertext(...)
    header = (
        MAGIC
        + struct.pack(">B", VERSION)
        + struct.pack(">III", SCRYPT_N, SCRYPT_R, SCRYPT_P)
        + salt
        + nonce
    )
    out_path.write_bytes(header + ciphertext)


def decrypt_file(in_path: str | Path, out_path: str | Path, password: str) -> None:
    in_path = Path(in_path)
    out_path = Path(out_path)

    data = in_path.read_bytes()
    if len(data) < 4 + 1 + 12 + SALT_LEN + NONCE_LEN:
        raise ValueError("File too short / not a valid PQE1 file")

    if data[:4] != MAGIC:
        raise ValueError("Bad magic (not a PQE1 file)")

    ver = data[4]
    if ver != VERSION:
        raise ValueError(f"Unsupported version: {ver}")

    n, r, p = struct.unpack(">III", data[5:5 + 12])
    salt_off = 5 + 12
    salt = data[salt_off:salt_off + SALT_LEN]
    nonce_off = salt_off + SALT_LEN
    nonce = data[nonce_off:nonce_off + NONCE_LEN]
    ciphertext = data[nonce_off + NONCE_LEN:]

    key = _derive_key(password, salt, n=n, r=r, p=p)
    aead = AESGCM(key)

    # If password is wrong or file tampered, this raises InvalidTag
    plaintext = aead.decrypt(nonce, ciphertext, associated_data=None)
    out_path.write_bytes(plaintext)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["enc", "dec"])
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--password", required=True)
    args = ap.parse_args()

    if args.mode == "enc":
        encrypt_file(args.src, args.dst, args.password)
    else:
        decrypt_file(args.src, args.dst, args.password)

   # encrypt_file("C:\\temp\\bbb.zip", "C:\\temp\\bbb.zip.enc", "your_password_here")
   # decrypt_file("C:\\temp\\bbb.zip.enc", "C:\\temp\\bbb2.zip", "your_password_here")
# python crypt.py enc secret.txt secret.pqe --password "une phrase de passe longue ..."
# python crypt.py dec secret.pqe recovered.txt --password "une phrase de passe longue ..."

