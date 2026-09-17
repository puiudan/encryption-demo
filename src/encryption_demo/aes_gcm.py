from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


LOGGER = logging.getLogger("encryption_demo")


@dataclass(frozen=True)
class AesGcmDemoResult:
    plaintext: str
    aad: str
    key_base64: str
    nonce_base64: str
    ciphertext_base64: str
    decrypted_plaintext: str
    decrypted_matches: bool
    tampered_verified: bool


def run_aes_gcm_demo(plaintext: str, aad: str) -> AesGcmDemoResult:
    LOGGER.info("Starting AES-GCM demo.")

    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)

    plaintext_bytes = plaintext.encode("utf-8")
    aad_bytes = aad.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad_bytes)
    LOGGER.info("Generated random AES-256 key and nonce.")
    LOGGER.info("Encrypted plaintext with AES-GCM.")

    decrypted = aesgcm.decrypt(nonce, ciphertext, aad_bytes)
    decrypted_plaintext = decrypted.decode("utf-8")
    decrypted_matches = decrypted_plaintext == plaintext
    LOGGER.info("Decryption with correct inputs succeeded: %s", decrypted_matches)

    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[-1] ^= 0x01
    try:
        aesgcm.decrypt(nonce, bytes(tampered_ciphertext), aad_bytes)
        tampered_verified = True
    except InvalidTag:
        tampered_verified = False
    LOGGER.info("Tampered ciphertext accepted: %s", tampered_verified)
    LOGGER.info("AES-GCM demo finished.")

    return AesGcmDemoResult(
        plaintext=plaintext,
        aad=aad,
        key_base64=base64.b64encode(key).decode("ascii"),
        nonce_base64=base64.b64encode(nonce).decode("ascii"),
        ciphertext_base64=base64.b64encode(ciphertext).decode("ascii"),
        decrypted_plaintext=decrypted_plaintext,
        decrypted_matches=decrypted_matches,
        tampered_verified=tampered_verified,
    )
