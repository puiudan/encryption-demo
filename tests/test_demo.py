import unittest

from encryption_demo.demo import run_demo


class DemoTests(unittest.TestCase):
    def test_demo_verifies_original_message_and_rejects_tampered_message(self) -> None:
        result = run_demo("unit test message")

        self.assertTrue(result.verified)
        self.assertFalse(result.tampered_verified)
        self.assertEqual(result.message, "unit test message")
        self.assertIn("BEGIN PUBLIC KEY", result.public_key_pem)
        self.assertTrue(result.signature_base64)


if __name__ == "__main__":
    unittest.main()

