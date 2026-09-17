import argparse

from .aes_gcm import run_aes_gcm_demo
from .logging_utils import configure_actor_logging
from .ml_dsa import run_ml_dsa_demo
from .ml_kem import run_ml_kem_demo
from .rsa_pss import run_rsa_pss_demo
from .sha256 import run_sha256_demo


def configure_logging() -> None:
    configure_actor_logging()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a verbose cryptography demo.",
    )
    parser.add_argument(
        "--demo",
        choices=["sha256", "aes-gcm", "rsa-pss", "ml-kem", "ml-dsa"],
        default="sha256",
        help="Demo type to run.",
    )
    parser.add_argument(
        "--message",
        default=None,
        help="Message or plaintext to use during the selected demo.",
    )
    parser.add_argument(
        "--aad",
        default=None,
        help="Additional authenticated data for --demo aes-gcm.",
    )

    args = parser.parse_args(argv)
    if args.demo != "aes-gcm" and args.aad is not None:
        parser.error("--aad is only supported with --demo aes-gcm")

    if args.demo == "sha256":
        if args.message is None:
            args.message = "Hello from the SHA-256 demo!"
        return args

    if args.demo == "aes-gcm":
        if args.message is None:
            args.message = "Hello from the AES-GCM demo!"
        if args.aad is None:
            args.aad = "encryption-demo-aad"
        return args

    if args.demo == "rsa-pss":
        if args.message is None:
            args.message = "Hello from the RSA-PSS demo!"
        return args

    if args.demo == "ml-kem":
        if args.message is not None:
            parser.error("--message is not supported with --demo ml-kem")
        return args

    if args.demo == "ml-dsa":
        if args.message is None:
            args.message = "Hello from the ML-DSA demo!"
        return args

    parser.error("Unsupported demo type.")


def main() -> int:
    configure_logging()
    args = parse_args()
    if args.demo == "aes-gcm":
        result = run_aes_gcm_demo(args.message, args.aad)
        return 0 if result.decrypted_matches and not result.modified_nonce_verified and not result.modified_aad_verified else 1
    if args.demo == "rsa-pss":
        result = run_rsa_pss_demo(args.message)
        return 0 if result.verified and not result.tampered_verified else 1
    if args.demo == "ml-kem":
        result = run_ml_kem_demo()
        return 0 if result.shared_secret_matches and not result.tampered_shared_secret_matches else 1
    if args.demo == "ml-dsa":
        result = run_ml_dsa_demo(args.message)
        return 0 if result.verified and not result.tampered_verified else 1

    run_sha256_demo(args.message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
