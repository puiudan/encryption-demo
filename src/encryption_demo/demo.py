import argparse
import logging
from .ecdhe import EcdheDemoResult, run_ecdhe_demo
from .ecdsa import EcdsaDemoResult, run_ecdsa_demo


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


LOGGER = logging.getLogger("encryption_demo")


def run_demo(message: str) -> EcdsaDemoResult:
    return run_ecdsa_demo(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a verbose ECDSA or ECDHE cryptography demo.",
    )
    parser.add_argument(
        "--demo",
        choices=["ecdsa", "ecdhe"],
        default="ecdsa",
        help="Demo type to run.",
    )
    parser.add_argument(
        "--message",
        default="Hello from the ECDSA demo!",
        help="Message to sign during the ECDSA demo.",
    )
    return parser.parse_args()


def main() -> int:
    configure_logging()
    args = parse_args()
    if args.demo == "ecdhe":
        result = run_ecdhe_demo()
        return 0 if result.shared_secret_matches and result.derived_key_matches else 1

    result = run_demo(args.message)
    return 0 if result.verified and not result.tampered_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
