# app/tests/test_keys.py

import unittest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from app.utilities import generate_private_key, generate_public_key_from_private, derive_shared_secret

class TestKeyGeneration(unittest.TestCase):
    def test_key_pair_generation(self):
        # Генерація приватного та публічного ключів
        private_key = generate_private_key()
        public_key = generate_public_key_from_private(private_key)
        
        # Перевірка, що ключі не порожні
        self.assertIsNotNone(private_key, "Private key should not be None")
        self.assertIsNotNone(public_key, "Public key should not be None")

    def test_shared_secret_derivation(self):
        # Генерація пари ключів для двох сторін
        private_key1 = generate_private_key()
        public_key1 = generate_public_key_from_private(private_key1)
        private_key2 = generate_private_key()
        public_key2 = generate_public_key_from_private(private_key2)

        # Отримання публічних ключів у байтах з правильними параметрами
        public_bytes1 = public_key1.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_bytes2 = public_key2.public_bytes(Encoding.Raw, PublicFormat.Raw)

        # Обчислення спільного секрету
        shared_secret1 = derive_shared_secret(private_key1, public_bytes2)
        shared_secret2 = derive_shared_secret(private_key2, public_bytes1)
        
        # Перевірка, що обидва секрети однакові
        self.assertEqual(shared_secret1, shared_secret2, "Shared secrets should match")

if __name__ == "__main__":
    unittest.main()
