from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
from dataclasses import dataclass


LOGGER = logging.getLogger("encryption_demo")


@dataclass(frozen=True)
class HmacSha256DemoResult:
    message: str
    message_hex: str
    tag_hex: str
    tag_base64: str
    verified: bool
    tampered_verified: bool
    wrong_key_verified: bool


def generate_hmac_tag(message: bytes, secret_key: bytes) -> bytes:
    return hmac.new(secret_key, message, hashlib.sha256).digest()


def verify_hmac_tag(message: bytes, secret_key: bytes, tag: bytes) -> bool:
    expected_tag = generate_hmac_tag(message, secret_key)
    return hmac.compare_digest(expected_tag, tag)


def run_hmac_sha256_demo(message: str, secret_key: str) -> HmacSha256DemoResult:
    LOGGER.info("Starting HMAC-SHA256 demo.")
    LOGGER.info("HMAC provides message authentication and integrity, not encryption.")

    message_bytes = message.encode("utf-8")
    secret_key_bytes = secret_key.encode("utf-8")
    message_hex = binascii.hexlify(message_bytes).decode("ascii")
    LOGGER.info("Prepared UTF-8 encoded input for HMAC processing.")

    tag = generate_hmac_tag(message_bytes, secret_key_bytes)
    tag_hex = tag.hex()
    tag_base64 = base64.b64encode(tag).decode("ascii")
    LOGGER.info("Computed HMAC-SHA256 tag (hex): %s", tag_hex)
    LOGGER.info("Computed HMAC-SHA256 tag (base64): %s", tag_base64)

    verified = verify_hmac_tag(message_bytes, secret_key_bytes, tag)
    LOGGER.info("Verification with the original message and key: %s", verified)

    tampered_message = f"{message} (tampered)".encode("utf-8")
    tampered_verified = verify_hmac_tag(tampered_message, secret_key_bytes, tag)
    LOGGER.info("Verification after tampering with the message: %s", tampered_verified)

    wrong_key_bytes = f"{secret_key}-wrong".encode("utf-8")
    wrong_key_verified = verify_hmac_tag(message_bytes, wrong_key_bytes, tag)
    LOGGER.info("Verification with the wrong key: %s", wrong_key_verified)
    LOGGER.info("HMAC-SHA256 demo finished.")

    return HmacSha256DemoResult(
        message=message,
        message_hex=message_hex,
        tag_hex=tag_hex,
        tag_base64=tag_base64,
        verified=verified,
        tampered_verified=tampered_verified,
        wrong_key_verified=wrong_key_verified,
    )
