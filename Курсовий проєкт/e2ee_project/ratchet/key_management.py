import logging
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class KeyManagement:
    def __init__(self, client_id):
        self.client_id = client_id
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        logging.info(f"{self.client_id} - Генерація нової пари ключів...")

    def generate_key_pair(self):
        logging.info('Генерація нової пари ключів...')
        # Використовуємо X25519 для генерації ключів, щоб мати можливість використовувати exchange
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()  # Отримання публічного ключа
        logging.debug(f'Приватний ключ: {self.private_key}')
        logging.debug(f'Публічний ключ: {self.public_key}')

    def get_public_key_bytes(self):
        logging.info('Отримання публічного ключа у байтах...')
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def derive_shared_secret(self, peer_public_key_bytes):
        logging.debug(f"{self.client_id} - Отримання публічного ключа партнера в байтах...")
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        logging.info(f"{self.client_id} - Отримано публічний ключ партнера: {peer_public_key_bytes.hex()}")

        shared_secret = self.private_key.exchange(peer_public_key)
        logging.info(f"{self.client_id} - Спільний секрет успішно розраховано: {shared_secret.hex()}")
        return shared_secret
