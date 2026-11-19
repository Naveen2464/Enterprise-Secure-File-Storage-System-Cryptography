import json
import unittest
from crypto_utils import generate_key_pair, encrypt_file, decrypt_file, verify_package_signature


class HybridCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recipient_private, cls.recipient_public = generate_key_pair()
        cls.sender_private, cls.sender_public = generate_key_pair()

    def test_encrypt_decrypt_round_trip(self):
        original = b"Classroom cryptography demonstration file."
        package = encrypt_file("sample.txt", original,
                               self.recipient_public, self.sender_private)
        self.assertTrue(verify_package_signature(package, self.sender_public))
        filename, recovered = decrypt_file(package, self.recipient_private, self.sender_public)
        self.assertEqual(filename, "sample.txt")
        self.assertEqual(recovered, original)

    def test_wrong_sender_key_fails_signature(self):
        _, other_public = generate_key_pair()
        package = encrypt_file("sample.txt", b"hello",
                               self.recipient_public, self.sender_private)
        self.assertFalse(verify_package_signature(package, other_public))

    def test_tampering_fails_signature(self):
        package = encrypt_file("sample.txt", b"hello",
                               self.recipient_public, self.sender_private)
        data = json.loads(package)
        data["filename"] = "changed.txt"
        changed = json.dumps(data).encode()
        self.assertFalse(verify_package_signature(changed, self.sender_public))

    def test_wrong_recipient_key_fails_decryption(self):
        _, wrong_private = generate_key_pair()
        package = encrypt_file("sample.txt", b"hello",
                               self.recipient_public, self.sender_private)
        with self.assertRaises(Exception):
            decrypt_file(package, wrong_private, self.sender_public)


if __name__ == "__main__":
    unittest.main()
