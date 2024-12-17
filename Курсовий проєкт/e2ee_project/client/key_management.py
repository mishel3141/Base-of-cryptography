from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import logging
import base64

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
        logging.info(f"Shared secret derived successfully.")
        return shared_secret

    def save_private_key(self, file_path, passphrase=None):
        """Зберігання приватного ключа у файл (зашифрованого за допомогою passphrase)."""
        # Генерація salt для PBKDF2
        salt = os.urandom(16)
        # Якщо passphrase не заданий, то використовуємо дефолтне значення
        if passphrase is None:
            passphrase = 'default_passphrase'
        
        # Генерація ключа для шифрування
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        encryption_key = kdf.derive(passphrase.encode())
        
        # Шифрування приватного ключа
        encrypted_private_key = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(encryption_key)
        )

        with open(file_path, 'wb') as f:
            # Записуємо salt перед зашифрованим приватним ключем для розшифровки
            f.write(salt + encrypted_private_key)
        logging.info(f"Private key saved to {file_path}")

    def load_private_key(self, file_path, passphrase=None):
        """Завантаження зашифрованого приватного ключа з файлу."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            salt = data[:16]
            encrypted_private_key = data[16:]

            if passphrase is None:
                passphrase = 'default_passphrase'
            
            # Генерація ключа для розшифровки
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            decryption_key = kdf.derive(passphrase.encode())
            
            # Розшифровка приватного ключа
            private_key = serialization.load_pem_private_key(
                encrypted_private_key, password=decryption_key, backend=default_backend()
            )
            self.private_key = private_key
            self.public_key = self.private_key.public_key()
            logging.info(f"Private key loaded from {file_path}")
        
        except Exception as e:
            logging.error(f"Failed to load private key: {e}")
            raise
