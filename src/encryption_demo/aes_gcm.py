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
    modified_nonce_verified: bool
    modified_aad_verified: bool


def run_aes_gcm_demo(plaintext: str, aad: str) -> AesGcmDemoResult:
    LOGGER.info("Starting AES-GCM demo.")
    LOGGER.info("Input plaintext (UTF-8 text): %s", plaintext)
    LOGGER.info("Input AAD (UTF-8 text): %s", aad)

    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    key_base64 = base64.b64encode(key).decode("ascii")
    nonce_base64 = base64.b64encode(nonce).decode("ascii")
    LOGGER.info("Generated AES key length (bits): %d", len(key) * 8)
    LOGGER.info("Generated nonce (base64): %s", nonce_base64)

    plaintext_bytes = plaintext.encode("utf-8")
    aad_bytes = aad.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad_bytes)
    ciphertext_base64 = base64.b64encode(ciphertext).decode("ascii")
    LOGGER.info("Generated random AES-256 key and nonce.")
    LOGGER.info("Encrypted plaintext with AES-GCM to ciphertext (base64): %s", ciphertext_base64)

    decrypted = aesgcm.decrypt(nonce, ciphertext, aad_bytes)
    decrypted_plaintext = decrypted.decode("utf-8")
    decrypted_matches = decrypted_plaintext == plaintext
    LOGGER.info("Decrypted plaintext (UTF-8 text): %s", decrypted_plaintext)
    LOGGER.info("Decryption with correct inputs succeeded: %s", decrypted_matches)

    tampered_nonce = bytearray(nonce)
    tampered_nonce[-1] ^= 0x01
    try:
        aesgcm.decrypt(bytes(tampered_nonce), ciphertext, aad_bytes)
        modified_nonce_verified = True
    except InvalidTag:
        modified_nonce_verified = False
    LOGGER.info("Verification with modified nonce accepted: %s", modified_nonce_verified)

    tampered_aad_bytes = aad_bytes + b"-tampered"
    try:
        aesgcm.decrypt(nonce, ciphertext, tampered_aad_bytes)
        modified_aad_verified = True
    except InvalidTag:
        modified_aad_verified = False
    LOGGER.info("Verification with modified AAD accepted: %s", modified_aad_verified)
    LOGGER.info("AES-GCM demo finished.")

    return AesGcmDemoResult(
        plaintext=plaintext,
        aad=aad,
        key_base64=key_base64,
        nonce_base64=nonce_base64,
        ciphertext_base64=ciphertext_base64,
        decrypted_plaintext=decrypted_plaintext,
        decrypted_matches=decrypted_matches,
        modified_nonce_verified=modified_nonce_verified,
        modified_aad_verified=modified_aad_verified,
    )
