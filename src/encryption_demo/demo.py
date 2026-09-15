from __future__ import annotations

import argparse
import base64
import binascii
import logging
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


LOGGER = logging.getLogger("encryption_demo")


@dataclass(frozen=True)
class DemoResult:
    message: str
    private_key_pem: str
    public_key_pem: str
    message_hex: str
    digest_sha256_hex: str
    signature_der_hex: str
    signature_base64: str
    signature_r_hex: str
    signature_s_hex: str
    verified: bool
    tampered_verified: bool


@dataclass(frozen=True)
class EcdheDemoResult:
    alice_public_key_pem: str
    bob_public_key_pem: str
    alice_shared_secret_hex: str
    bob_shared_secret_hex: str
    alice_derived_key_hex: str
    bob_derived_key_hex: str
    shared_secret_matches: bool
    derived_key_matches: bool


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def verify_signature(
    public_key: ec.EllipticCurvePublicKey,
    message: bytes,
    signature: bytes,
) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def run_demo(message: str) -> DemoResult:
    LOGGER.info("Starting ECDSA demo.")
    LOGGER.info("ECDSA is a digital signature algorithm, not an encryption algorithm.")

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    LOGGER.info("Generated a P-256 key pair.")
    LOGGER.info("Private key (PEM):\n%s", private_key_pem.strip())
    LOGGER.info("Public key:\n%s", public_key_pem.strip())
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers
    LOGGER.info("Private scalar d (hex): %064x", private_numbers.private_value)
    LOGGER.info("Public point X (hex): %064x", public_numbers.x)
    LOGGER.info("Public point Y (hex): %064x", public_numbers.y)

    message_bytes = message.encode("utf-8")
    message_hex = binascii.hexlify(message_bytes).decode("ascii")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message_bytes)
    digest_sha256_hex = digest.finalize().hex()
    LOGGER.info("Signing message: %s", message)
    LOGGER.info("Message bytes (hex): %s", message_hex)
    LOGGER.info("SHA-256 digest (hex): %s", digest_sha256_hex)
    signature = private_key.sign(message_bytes, ec.ECDSA(hashes.SHA256()))
    signature_der_hex = signature.hex()
    signature_base64 = base64.b64encode(signature).decode("ascii")
    signature_r, signature_s = decode_dss_signature(signature)
    signature_r_hex = f"{signature_r:064x}"
    signature_s_hex = f"{signature_s:064x}"
    LOGGER.info("Generated signature (DER hex): %s", signature_der_hex)
    LOGGER.info("Generated signature (base64): %s", signature_base64)
    LOGGER.info("Signature component r (hex): %s", signature_r_hex)
    LOGGER.info("Signature component s (hex): %s", signature_s_hex)

    verified = verify_signature(public_key, message_bytes, signature)
    LOGGER.info("Verification with the original message: %s", verified)

    tampered_message = f"{message} (tampered)".encode("utf-8")
    tampered_verified = verify_signature(public_key, tampered_message, signature)
    LOGGER.info("Verification after tampering with the message: %s", tampered_verified)
    LOGGER.info("ECDSA demo finished.")

    return DemoResult(
        message=message,
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
        message_hex=message_hex,
        digest_sha256_hex=digest_sha256_hex,
        signature_der_hex=signature_der_hex,
        signature_base64=signature_base64,
        signature_r_hex=signature_r_hex,
        signature_s_hex=signature_s_hex,
        verified=verified,
        tampered_verified=tampered_verified,
    )


def run_ecdhe_demo() -> EcdheDemoResult:
    LOGGER.info("Starting ECDHE demo.")
    LOGGER.info("ECDHE is a key exchange mechanism, not a digital signature algorithm.")

    alice_private_key = ec.generate_private_key(ec.SECP256R1())
    bob_private_key = ec.generate_private_key(ec.SECP256R1())
    alice_public_key = alice_private_key.public_key()
    bob_public_key = bob_private_key.public_key()
    alice_public_key_pem = alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    bob_public_key_pem = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    LOGGER.info("Generated ephemeral P-256 key pairs for Alice and Bob.")
    LOGGER.info("Alice public key:\n%s", alice_public_key_pem.strip())
    LOGGER.info("Bob public key:\n%s", bob_public_key_pem.strip())

    alice_shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)
    bob_shared_secret = bob_private_key.exchange(ec.ECDH(), alice_public_key)
    alice_shared_secret_hex = alice_shared_secret.hex()
    bob_shared_secret_hex = bob_shared_secret.hex()
    LOGGER.info("Alice shared secret (hex): %s", alice_shared_secret_hex)
    LOGGER.info("Bob shared secret (hex): %s", bob_shared_secret_hex)

    alice_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"encryption-demo-ecdhe",
    ).derive(alice_shared_secret)
    bob_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"encryption-demo-ecdhe",
    ).derive(bob_shared_secret)
    alice_derived_key_hex = alice_derived_key.hex()
    bob_derived_key_hex = bob_derived_key.hex()
    LOGGER.info("Alice derived key (HKDF-SHA256, hex): %s", alice_derived_key_hex)
    LOGGER.info("Bob derived key (HKDF-SHA256, hex): %s", bob_derived_key_hex)

    shared_secret_matches = alice_shared_secret == bob_shared_secret
    derived_key_matches = alice_derived_key == bob_derived_key
    LOGGER.info("Shared secret match: %s", shared_secret_matches)
    LOGGER.info("Derived key match: %s", derived_key_matches)
    LOGGER.info("ECDHE demo finished.")

    return EcdheDemoResult(
        alice_public_key_pem=alice_public_key_pem,
        bob_public_key_pem=bob_public_key_pem,
        alice_shared_secret_hex=alice_shared_secret_hex,
        bob_shared_secret_hex=bob_shared_secret_hex,
        alice_derived_key_hex=alice_derived_key_hex,
        bob_derived_key_hex=bob_derived_key_hex,
        shared_secret_matches=shared_secret_matches,
        derived_key_matches=derived_key_matches,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a verbose ECDSA or ECDHE cryptography demo.",
    )
    parser.add_argument(
        "--demo",
        choices=["ecdsa", "ecdhe"],
        default="ecdsa",
        help="Demo type to run.",
    )
    parser.add_argument(
        "--message",
        default="Hello from the ECDSA demo!",
        help="Message to sign during the ECDSA demo.",
    )
    return parser.parse_args()


def main() -> int:
    configure_logging()
    args = parse_args()
    if args.demo == "ecdhe":
        result = run_ecdhe_demo()
        return 0 if result.shared_secret_matches and result.derived_key_matches else 1

    result = run_demo(args.message)
    return 0 if result.verified and not result.tampered_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
