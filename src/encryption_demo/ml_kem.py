from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import mlkem

from .logging_utils import get_actor_logger

LOGGER = get_actor_logger("ML-KEM")


@dataclass(frozen=True)
class MlKemDemoResult:
    private_key_base64: str
    public_key_base64: str
    ciphertext_base64: str
    encapsulated_shared_secret_hex: str
    decapsulated_shared_secret_hex: str
    tampered_decapsulated_shared_secret_hex: str
    tampered_decapsulation_succeeded: bool
    shared_secret_matches: bool
    tampered_shared_secret_matches: bool


def run_ml_kem_demo() -> MlKemDemoResult:
    LOGGER.info("Starting ML-KEM demo.")
    LOGGER.info("ML-KEM is a key encapsulation mechanism for key exchange.")

    private_key = mlkem.MLKEM768PrivateKey.generate()
    public_key = private_key.public_key()
    private_key_base64 = base64.b64encode(private_key.private_bytes_raw()).decode("ascii")
    public_key_base64 = base64.b64encode(public_key.public_bytes_raw()).decode("ascii")
    LOGGER.info("Generated ML-KEM-768 key pair.")
    LOGGER.info("Generated private/public key bytes for demo result export.")
    LOGGER.info("Public key (raw, base64): %s", public_key_base64)

    encapsulated_shared_secret, ciphertext = public_key.encapsulate()
    decapsulated_shared_secret = private_key.decapsulate(ciphertext)
    ciphertext_base64 = base64.b64encode(ciphertext).decode("ascii")
    encapsulated_shared_secret_hex = encapsulated_shared_secret.hex()
    decapsulated_shared_secret_hex = decapsulated_shared_secret.hex()
    LOGGER.info("Ciphertext (base64): %s", ciphertext_base64)
    LOGGER.info("Encapsulated shared secret (hex): %s", encapsulated_shared_secret_hex)
    LOGGER.info("Decapsulated shared secret (hex): %s", decapsulated_shared_secret_hex)

    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0x01
    try:
        tampered_decapsulated_shared_secret = private_key.decapsulate(bytes(tampered_ciphertext))
        tampered_decapsulation_succeeded = True
        tampered_decapsulated_shared_secret_hex = tampered_decapsulated_shared_secret.hex()
    except (ValueError, TypeError):
        tampered_decapsulation_succeeded = False
        tampered_decapsulated_shared_secret = b""
        tampered_decapsulated_shared_secret_hex = ""
    LOGGER.info(
        "Tampered ciphertext decapsulation succeeded: %s",
        tampered_decapsulation_succeeded,
    )
    LOGGER.info(
        "Tampered ciphertext decapsulation shared secret (hex): %s",
        tampered_decapsulated_shared_secret_hex,
    )

    shared_secret_matches = encapsulated_shared_secret == decapsulated_shared_secret
    tampered_shared_secret_matches = encapsulated_shared_secret == tampered_decapsulated_shared_secret
    LOGGER.info("Shared secret match for original ciphertext: %s", shared_secret_matches)
    LOGGER.info("Shared secret match for tampered ciphertext: %s", tampered_shared_secret_matches)
    LOGGER.info("ML-KEM demo finished.")

    return MlKemDemoResult(
        private_key_base64=private_key_base64,
        public_key_base64=public_key_base64,
        ciphertext_base64=ciphertext_base64,
        encapsulated_shared_secret_hex=encapsulated_shared_secret_hex,
        decapsulated_shared_secret_hex=decapsulated_shared_secret_hex,
        tampered_decapsulated_shared_secret_hex=tampered_decapsulated_shared_secret_hex,
        tampered_decapsulation_succeeded=tampered_decapsulation_succeeded,
        shared_secret_matches=shared_secret_matches,
        tampered_shared_secret_matches=tampered_shared_secret_matches,
    )
