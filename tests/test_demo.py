import base64
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa

from encryption_demo.aes_gcm import run_aes_gcm_demo
from encryption_demo.demo import parse_args
from encryption_demo.rsa_pss import run_rsa_pss_demo, verify_signature
from encryption_demo.sha256 import run_sha256_demo


class DemoTests(unittest.TestCase):
    def test_sha256_demo_changes_digest_when_message_changes(self) -> None:
        result = run_sha256_demo("unit test message")

        self.assertEqual(result.message, "unit test message")
        self.assertEqual(result.message_hex, "756e69742074657374206d657373616765")
        self.assertEqual(len(result.digest_hex), 64)
        self.assertEqual(len(result.tampered_digest_hex), 64)
        self.assertFalse(result.digests_match)

    def test_aes_gcm_demo_decrypts_original_and_rejects_tampering(self) -> None:
        result = run_aes_gcm_demo("unit test plaintext", "unit test aad")

        self.assertEqual(result.plaintext, "unit test plaintext")
        self.assertEqual(result.aad, "unit test aad")
        self.assertEqual(result.decrypted_plaintext, "unit test plaintext")
        self.assertTrue(result.decrypted_matches)
        self.assertFalse(result.modified_nonce_verified)
        self.assertFalse(result.modified_aad_verified)
        nonce_bytes = base64.b64decode(result.nonce_base64)
        ciphertext_bytes = base64.b64decode(result.ciphertext_base64)
        self.assertEqual(result.key_size_bits, 256)
        self.assertEqual(len(nonce_bytes), 12)
        self.assertGreaterEqual(len(ciphertext_bytes), 16)

    def test_aes_gcm_demo_with_empty_inputs_still_rejects_tampering(self) -> None:
        result = run_aes_gcm_demo("", "")

        self.assertEqual(result.plaintext, "")
        self.assertEqual(result.aad, "")
        self.assertEqual(result.decrypted_plaintext, "")
        self.assertTrue(result.decrypted_matches)
        self.assertFalse(result.modified_nonce_verified)
        self.assertFalse(result.modified_aad_verified)

    def test_rsa_pss_demo_verifies_original_message_and_rejects_tampered_message(self) -> None:
        result = run_rsa_pss_demo("unit test message")

        self.assertTrue(result.verified)
        self.assertFalse(result.tampered_verified)
        self.assertEqual(result.message, "unit test message")
        self.assertIn("BEGIN PUBLIC KEY", result.public_key_pem)
        self.assertTrue(result.signature_base64)

    def test_rsa_pss_verify_signature_rejects_malformed_signature(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        self.assertFalse(verify_signature(public_key, b"unit test message", b"malformed"))

    def test_parse_args_rejects_invalid_demo_specific_arguments(self) -> None:
        invalid_argv_sets = [
            ["--demo", "sha256", "--aad", "unit test aad"],
            ["--aad", "unit test aad", "--demo", "rsa-pss"],
        ]

        for argv in invalid_argv_sets:
            with self.subTest(argv=argv):
                with self.assertRaises(SystemExit):
                    parse_args(argv)

    def test_parse_args_preserves_explicit_empty_strings_for_supported_demos(self) -> None:
        sha256_args = parse_args(["--demo", "sha256", "--message", ""])
        aes_gcm_args = parse_args(["--demo", "aes-gcm", "--message", "", "--aad", ""])

        self.assertEqual(sha256_args.message, "")
        self.assertEqual(aes_gcm_args.message, "")
        self.assertEqual(aes_gcm_args.aad, "")


if __name__ == "__main__":
    unittest.main()
