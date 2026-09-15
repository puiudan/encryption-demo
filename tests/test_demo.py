import unittest

from encryption_demo.demo import run_demo, run_ecdhe_demo


class DemoTests(unittest.TestCase):
    def test_demo_verifies_original_message_and_rejects_tampered_message(self) -> None:
        result = run_demo("unit test message")

        self.assertTrue(result.verified)
        self.assertFalse(result.tampered_verified)
        self.assertEqual(result.message, "unit test message")
        self.assertIn("BEGIN PUBLIC KEY", result.public_key_pem)
        self.assertTrue(result.signature_base64)

    def test_ecdhe_demo_produces_matching_shared_secret_and_derived_key(self) -> None:
        result = run_ecdhe_demo()

        self.assertTrue(result.shared_secret_matches)
        self.assertTrue(result.derived_key_matches)
        self.assertEqual(result.alice_shared_secret_hex, result.bob_shared_secret_hex)
        self.assertEqual(result.alice_derived_key_hex, result.bob_derived_key_hex)
        self.assertIn("BEGIN PUBLIC KEY", result.alice_public_key_pem)
        self.assertIn("BEGIN PUBLIC KEY", result.bob_public_key_pem)


if __name__ == "__main__":
    unittest.main()
