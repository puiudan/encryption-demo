import argparse
import logging

from .ecdhe import EcdheDemoResult, run_ecdhe_demo
from .ecdsa import EcdsaDemoResult, run_ecdsa_demo
from .hmac_sha256 import HmacSha256DemoResult, run_hmac_sha256_demo


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


LOGGER = logging.getLogger("encryption_demo")


def run_demo(message: str) -> EcdsaDemoResult:
    return run_ecdsa_demo(message)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a verbose ECDSA, ECDHE, or HMAC-SHA256 cryptography demo.",
    )
    parser.add_argument(
        "--demo",
        choices=["ecdsa", "ecdhe", "hmac"],
        default="ecdsa",
        help="Demo type to run.",
    )
    parser.add_argument(
        "--message",
        default=None,
        help="Message to use during the selected demo.",
    )
    parser.add_argument(
        "--key",
        default=None,
        help="Secret key to use during the HMAC-SHA256 demo.",
    )

    args = parser.parse_args(argv)
    if args.demo == "ecdhe":
        if args.message is not None:
            parser.error("--message is only supported with --demo ecdsa or --demo hmac")
        if args.key is not None:
            parser.error("--key is only supported with --demo hmac")
        return args

    if args.key is not None and args.demo != "hmac":
        parser.error("--key is only supported with --demo hmac")

    if args.demo == "ecdsa":
        if args.message is None:
            args.message = "Hello from the ECDSA demo!"
        return args

    if args.message is None:
        args.message = "Hello from the HMAC-SHA256 demo!"
    if args.key is None:
        parser.error("--key is required with --demo hmac")
    return args


def main() -> int:
    configure_logging()
    args = parse_args()
    if args.demo == "ecdhe":
        result = run_ecdhe_demo()
        return 0 if result.shared_secret_matches and result.derived_key_matches else 1
    if args.demo == "hmac":
        result = run_hmac_sha256_demo(args.message, args.key)
        return 0 if result.verified and not result.tampered_verified and not result.wrong_key_verified else 1

    result = run_demo(args.message)
    return 0 if result.verified and not result.tampered_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
