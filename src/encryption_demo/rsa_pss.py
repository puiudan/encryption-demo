from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .logging_utils import get_actor_logger

LOGGER = get_actor_logger("RSA-PSS")


@dataclass(frozen=True)
class RsaPssDemoResult:
    message: str
    private_key_pem: str
    public_key_pem: str
    signature_base64: str
    verified: bool
    tampered_verified: bool


def verify_signature(public_key: RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """Return False for invalid or malformed RSA-PSS signatures instead of raising."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def run_rsa_pss_demo(message: str) -> RsaPssDemoResult:
    LOGGER.info("Starting RSA-PSS demo.")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
    LOGGER.info("Generated RSA private key with size: %d bits", private_key.key_size)
    LOGGER.info("Generated RSA private key material for demo result export.")
    LOGGER.info("Generated RSA public key (PEM, escaped newlines): %s", public_key_pem.strip().replace("\n", "\\n"))

    message_bytes = message.encode("utf-8")
    LOGGER.info("Input message length (bytes): %d", len(message_bytes))
    signature = private_key.sign(
        message_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    signature_base64 = base64.b64encode(signature).decode("ascii")
    LOGGER.info("Generated RSA-PSS signature length (bytes): %d", len(signature))
    LOGGER.info("Generated RSA-PSS signature preview (base64): %s...", signature_base64[:32])
    LOGGER.info("Generated RSA key pair and RSA-PSS signature.")

    verified = verify_signature(public_key, message_bytes, signature)
    tampered_message = f"{message} (tampered)".encode("utf-8")
    LOGGER.info("Attempting verification with a tampered message variant.")
    tampered_verified = verify_signature(public_key, tampered_message, signature)
    LOGGER.info("Verification with original message: %s", verified)
    LOGGER.info("Verification with tampered message: %s", tampered_verified)
    LOGGER.info("RSA-PSS demo finished.")

    return RsaPssDemoResult(
        message=message,
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
        signature_base64=signature_base64,
        verified=verified,
        tampered_verified=tampered_verified,
    )
