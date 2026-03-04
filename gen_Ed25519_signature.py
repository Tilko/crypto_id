#!/usr/bin/env python3

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def generate_keypair(
    private_path: Path,
    public_path: Path,
    password: bytes | None = None,
):
    # 1️⃣ Génération clé privée
    private_key = ed25519.Ed25519PrivateKey.generate()

    # 2️⃣ Sérialisation clé privée
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    private_path.write_bytes(private_bytes)

    # 3️⃣ Extraction clé publique
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    public_path.write_bytes(public_bytes)

    print(f"Private key written to: {private_path}")
    print(f"Public key written to:  {public_path}")


if __name__ == "__main__":
    out_dir = Path("keys")
    out_dir.mkdir(exist_ok=True)

    private_file = out_dir / "private.pem"
    public_file = out_dir / "public.pem"

    # 🔐 Mets un mot de passe ici si tu veux protéger la clé
    PASSWORD = "".encode("utf-8")
    # PASSWORD = b"mot_de_passe_tres_solide"

    generate_keypair(private_file, public_file, PASSWORD)


# actions:
# - mis public.pem sur github/Tilko/crypto_id
# - installer ots: pip install opentimestamps-client
# PS C:\Users\marti\OneDrive\Documents\general_common_utilities\python\cryptography> ots upgrade keys/public.pem.ots
# Got 1 attestation(s) from https://alice.btc.calendar.opentimestamps.org
# Got 1 attestation(s) from https://finney.calendar.eternitywall.com
# Got 1 attestation(s) from https://btc.calendar.catallaxy.com
# Got 1 attestation(s) from https://bob.btc.calendar.opentimestamps.org
# Success! Timestamp complete
