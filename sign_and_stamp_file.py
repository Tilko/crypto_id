#!/usr/bin/env python3

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Optional, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


def sha256_file(path: Path) -> bytes:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.digest()


def load_ed25519_private_key(
    path: Path, password: Optional[bytes]
) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(
            f"Expected an Ed25519 private key, got {type(key).__name__}. "
            "Generate with: openssl genpkey -algorithm Ed25519 -out private.pem"
        )
    return cast(Ed25519PrivateKey, key)


def load_ed25519_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(
            f"Expected an Ed25519 public key, got {type(key).__name__}. "
            "Generate with: openssl pkey -in private.pem -pubout -out public.pem"
        )
    return cast(Ed25519PublicKey, key)


def ots_stamp(path: Path) -> None:
    p = subprocess.run(["ots", "stamp", str(path)])
    if p.returncode != 0:
        raise RuntimeError("ots stamp failed")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sign SHA256(document) with Ed25519, stamp signature with OpenTimestamps, then verify signature."
    )
    parser.add_argument("document", type=Path, help="Document to sign")
    script_dir = Path(__file__).resolve().parent
    parser.add_argument(
        "--key",
        type=Path,
        default=script_dir / "keys" / "private.pem",
        help="Ed25519 private key PEM",
    )
    parser.add_argument(
        "--pub",
        type=Path,
        default=script_dir / "keys" / "public.pem",
        help="Ed25519 public key PEM",
    )
    parser.add_argument(
        "--password", type=str, default=None, help="Password for encrypted private key"
    )
    args = parser.parse_args()

    if not args.document.exists():
        print(f"ERROR: document not found: {args.document}", file=sys.stderr)
        return 1
    if not args.key.exists():
        print(f"ERROR: private key not found: {args.key}", file=sys.stderr)
        return 1
    if not args.pub.exists():
        print(f"ERROR: public key not found: {args.pub}", file=sys.stderr)
        return 1

    password_bytes = args.password.encode("utf-8") if args.password else None

    # 1) Hash document
    doc_hash = sha256_file(args.document)

    # 2) Load keys
    private_key = load_ed25519_private_key(args.key, password_bytes)
    public_key = load_ed25519_public_key(args.pub)

    # 3) Sign hash
    signature = private_key.sign(doc_hash)
    sig_path = args.document.with_suffix(args.document.suffix + ".sig")
    sig_path.write_bytes(signature)
    print(f"Signature written to: {sig_path}")
    # 4) Verify signature (local)
    try:
        read_sig = sig_path.read_bytes()
        public_key.verify(read_sig, doc_hash)
        print("Signature verify: OK")
    except InvalidSignature:
        print(
            "Signature verify: FAIL (public.pem does not match private.pem or data changed)",
            file=sys.stderr,
        )
        return 2

    # 5) OTS stamp signature
    print("Stamping signature with OpenTimestamps...")
    # print("no stamp done to test")
    ots_stamp(sig_path)
    print("If stamping failed:")
    print(
        f"run:\nots stamp {sig_path}\n from the folder containing the signature file to get the timestamp proof"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
