from __future__ import annotations

import base64
import binascii
import logging
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa


LOGGER = logging.getLogger("encryption_demo")


@dataclass(frozen=True)
class MlDsaDemoResult:
    message: str
    private_key_base64: str
    public_key_base64: str
    message_hex: str
    signature_base64: str
    verified: bool
    tampered_verified: bool


def verify_signature(public_key: mldsa.MLDSA65PublicKey, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def run_ml_dsa_demo(message: str) -> MlDsaDemoResult:
    LOGGER.info("Starting ML-DSA demo.")
    LOGGER.info("ML-DSA is a post-quantum digital signature algorithm.")

    private_key = mldsa.MLDSA65PrivateKey.generate()
    public_key = private_key.public_key()
    private_key_base64 = base64.b64encode(private_key.private_bytes_raw()).decode("ascii")
    public_key_base64 = base64.b64encode(public_key.public_bytes_raw()).decode("ascii")
    LOGGER.info("Generated ML-DSA-65 key pair.")
    LOGGER.info("Private key (raw, base64): %s", private_key_base64)
    LOGGER.info("Public key (raw, base64): %s", public_key_base64)

    message_bytes = message.encode("utf-8")
    message_hex = binascii.hexlify(message_bytes).decode("ascii")
    signature = private_key.sign(message_bytes)
    signature_base64 = base64.b64encode(signature).decode("ascii")
    LOGGER.info("Message bytes (hex): %s", message_hex)
    LOGGER.info("Signature (base64): %s", signature_base64)

    verified = verify_signature(public_key, signature, message_bytes)
    LOGGER.info("Verification with the original message: %s", verified)

    tampered_message = f"{message} (tampered)".encode("utf-8")
    tampered_verified = verify_signature(public_key, signature, tampered_message)
    LOGGER.info("Verification after tampering with the message: %s", tampered_verified)
    LOGGER.info("ML-DSA demo finished.")

    return MlDsaDemoResult(
        message=message,
        private_key_base64=private_key_base64,
        public_key_base64=public_key_base64,
        message_hex=message_hex,
        signature_base64=signature_base64,
        verified=verified,
        tampered_verified=tampered_verified,
    )
