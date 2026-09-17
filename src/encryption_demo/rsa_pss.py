from __future__ import annotations

import base64
import logging
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


LOGGER = logging.getLogger("encryption_demo")


@dataclass(frozen=True)
class RsaPssDemoResult:
    message: str
    public_key_pem: str
    signature_base64: str
    verified: bool
    tampered_verified: bool


def verify_signature(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
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
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    message_bytes = message.encode("utf-8")
    signature = private_key.sign(
        message_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    signature_base64 = base64.b64encode(signature).decode("ascii")
    LOGGER.info("Generated RSA key pair and RSA-PSS signature.")

    verified = verify_signature(public_key, message_bytes, signature)
    tampered_message = f"{message} (tampered)".encode("utf-8")
    tampered_verified = verify_signature(public_key, tampered_message, signature)
    LOGGER.info("Verification with original message: %s", verified)
    LOGGER.info("Verification with tampered message: %s", tampered_verified)
    LOGGER.info("RSA-PSS demo finished.")

    return RsaPssDemoResult(
        message=message,
        public_key_pem=public_key_pem,
        signature_base64=signature_base64,
        verified=verified,
        tampered_verified=tampered_verified,
    )
