from __future__ import annotations

import argparse
import base64
import logging
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


LOGGER = logging.getLogger("encryption_demo")


@dataclass(frozen=True)
class DemoResult:
    message: str
    public_key_pem: str
    signature_base64: str
    verified: bool
    tampered_verified: bool


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
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    LOGGER.info("Generated a P-256 key pair.")
    LOGGER.info("Public key:\n%s", public_key_pem.strip())

    message_bytes = message.encode("utf-8")
    LOGGER.info("Signing message: %s", message)
    signature = private_key.sign(message_bytes, ec.ECDSA(hashes.SHA256()))
    signature_base64 = base64.b64encode(signature).decode("ascii")
    LOGGER.info("Generated signature (base64): %s", signature_base64)

    verified = verify_signature(public_key, message_bytes, signature)
    LOGGER.info("Verification with the original message: %s", verified)

    tampered_message = f"{message} (tampered)".encode("utf-8")
    tampered_verified = verify_signature(public_key, tampered_message, signature)
    LOGGER.info("Verification after tampering with the message: %s", tampered_verified)
    LOGGER.info("ECDSA demo finished.")

    return DemoResult(
        message=message,
        public_key_pem=public_key_pem,
        signature_base64=signature_base64,
        verified=verified,
        tampered_verified=tampered_verified,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a verbose ECDSA signing and verification demo.",
    )
    parser.add_argument(
        "--message",
        default="Hello from the ECDSA demo!",
        help="Message to sign during the demo.",
    )
    return parser.parse_args()


def main() -> int:
    configure_logging()
    args = parse_args()
    result = run_demo(args.message)
    return 0 if result.verified and not result.tampered_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())

