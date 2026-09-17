import argparse
import logging

from .aes_gcm import run_aes_gcm_demo
from .rsa_pss import run_rsa_pss_demo
from .sha256 import run_sha256_demo


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


LOGGER = logging.getLogger("encryption_demo")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a verbose SHA-256, AES-GCM, or RSA-PSS cryptography demo.",
    )
    parser.add_argument(
        "--demo",
        choices=["sha256", "aes-gcm", "rsa-pss"],
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

    parser.error("Unsupported demo type.")


def main() -> int:
    configure_logging()
    args = parse_args()
    if args.demo == "aes-gcm":
        result = run_aes_gcm_demo(args.message, args.aad)
        return 0 if result.decrypted_matches and not result.modified_input_verified else 1
    if args.demo == "rsa-pss":
        result = run_rsa_pss_demo(args.message)
        return 0 if result.verified and not result.tampered_verified else 1

    result = run_sha256_demo(args.message)
    return 0 if not result.digests_match else 1


if __name__ == "__main__":
    raise SystemExit(main())
