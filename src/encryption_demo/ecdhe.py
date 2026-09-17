from __future__ import annotations

import logging
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


LOGGER = logging.getLogger("encryption_demo")


@dataclass(frozen=True)
class EcdheDemoResult:
    alice_private_key_pem: str
    bob_private_key_pem: str
    alice_public_key_pem: str
    bob_public_key_pem: str
    alice_shared_secret_hex: str
    bob_shared_secret_hex: str
    alice_derived_key_hex: str
    bob_derived_key_hex: str
    shared_secret_matches: bool
    derived_key_matches: bool


def run_ecdhe_demo() -> EcdheDemoResult:
    LOGGER.info("Starting ECDHE demo.")
    LOGGER.info("ECDHE is a key exchange mechanism, not a digital signature algorithm.")

    alice_private_key = ec.generate_private_key(ec.SECP256R1())
    bob_private_key = ec.generate_private_key(ec.SECP256R1())
    alice_public_key = alice_private_key.public_key()
    bob_public_key = bob_private_key.public_key()
    alice_private_key_pem = alice_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    bob_private_key_pem = bob_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    alice_public_key_pem = alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    bob_public_key_pem = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    LOGGER.info("Generated ephemeral P-256 key pairs for Alice and Bob.")
    LOGGER.info("Alice private key:\n%s", alice_private_key_pem.strip())
    LOGGER.info("Bob private key:\n%s", bob_private_key_pem.strip())
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
        alice_private_key_pem=alice_private_key_pem,
        bob_private_key_pem=bob_private_key_pem,
        alice_public_key_pem=alice_public_key_pem,
        bob_public_key_pem=bob_public_key_pem,
        alice_shared_secret_hex=alice_shared_secret_hex,
        bob_shared_secret_hex=bob_shared_secret_hex,
        alice_derived_key_hex=alice_derived_key_hex,
        bob_derived_key_hex=bob_derived_key_hex,
        shared_secret_matches=shared_secret_matches,
        derived_key_matches=derived_key_matches,
    )
