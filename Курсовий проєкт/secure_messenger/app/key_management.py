# app/key_management.py

from cryptography.hazmat.primitives import serialization  
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
import logging


class KeyManagement:
    def __init__(self, client_id):
        self.client_id = client_id
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        logging.info(f"{self.client_id} - Генерація нової пари ключів...")

    def generate_key_pair(self):
        """Генерація нової пари ключів."""
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def get_public_key_bytes(self):
        """Отримання публічного ключа у байтах."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def derive_shared_secret(self, peer_public_key_bytes):
        """Обчислення спільного секрету з публічним ключем партнера."""
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_secret = self.private_key.exchange(peer_public_key)
        logging.info(f"Shared secret: {shared_secret.hex()}")
        return shared_secret

