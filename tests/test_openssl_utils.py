"""Unit tests for OpenSSL CLI utilities."""
import unittest
from crypto_utils import generate_key_pair
import openssl_utils


class OpenSSLUtilsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv_pem, cls.pub_pem = generate_key_pair()

    def test_version_detection(self):
        ver = openssl_utils.get_openssl_version()
        self.assertIn("OpenSSL", ver)

    def test_key_inspection(self):
        cmd, text = openssl_utils.inspect_rsa_key(self.priv_pem, is_public=False)
        self.assertIn("3072 bit", text)
        self.assertIn("modulus", text.lower())

    def test_digest(self):
        data = b"Enterprise Data Integrity Test"
        cmd, digest_hex = openssl_utils.openssl_digest(data, "sha256")
        self.assertEqual(len(digest_hex), 64)

    def test_sign_and_verify(self):
        data = b"Confidential Financial Audit Report"
        cmd_sign, sig = openssl_utils.openssl_sign(data, self.priv_pem)
        self.assertGreater(len(sig), 0)

        cmd_ver, is_valid, msg = openssl_utils.openssl_verify(data, sig, self.pub_pem)
        self.assertTrue(is_valid)

        # Tamper test
        tampered_data = b"Confidential Financial Audit Report - TAMPERED"
        _, is_valid_tampered, _ = openssl_utils.openssl_verify(tampered_data, sig, self.pub_pem)
        self.assertFalse(is_valid_tampered)

    def test_symmetric_roundtrip(self):
        plaintext = b"Classified Payload at 2026-11-19"
        password = "EnterpriseSecurePassword123!"
        _, ct = openssl_utils.openssl_symmetric_encrypt(plaintext, password)
        _, recovered = openssl_utils.openssl_symmetric_decrypt(ct, password)
        self.assertEqual(recovered, plaintext)


if __name__ == "__main__":
    unittest.main()

