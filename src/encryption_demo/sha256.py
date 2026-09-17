from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass


LOGGER = logging.getLogger("encryption_demo")


@dataclass(frozen=True)
class Sha256DemoResult:
    message: str
    message_hex: str
    digest_hex: str
    tampered_digest_hex: str
    digests_match: bool


def run_sha256_demo(message: str) -> Sha256DemoResult:
    LOGGER.info("Starting SHA-256 demo.")
    LOGGER.info("Input message (UTF-8 text): %s", message)

    message_bytes = message.encode("utf-8")
    message_hex = message_bytes.hex()
    LOGGER.info("Input message length (bytes): %d", len(message_bytes))
    digest_hex = hashlib.sha256(message_bytes).hexdigest()
    LOGGER.info("Message bytes (hex): %s", message_hex)
    LOGGER.info("SHA-256 digest (hex): %s", digest_hex)

    tampered_message = f"{message} (tampered)"
    tampered_bytes = tampered_message.encode("utf-8")
    LOGGER.info("Tampered input message (UTF-8 text): %s", tampered_message)
    tampered_digest_hex = hashlib.sha256(tampered_bytes).hexdigest()
    digests_match = digest_hex == tampered_digest_hex
    LOGGER.info("Tampered SHA-256 digest (hex): %s", tampered_digest_hex)
    LOGGER.info("Original and tampered digests match: %s", digests_match)
    LOGGER.info("SHA-256 demo finished.")

    return Sha256DemoResult(
        message=message,
        message_hex=message_hex,
        digest_hex=digest_hex,
        tampered_digest_hex=tampered_digest_hex,
        digests_match=digests_match,
    )
