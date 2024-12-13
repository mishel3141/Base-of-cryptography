import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from app.config import logger  # Імпортуємо налаштований логгер

class DoubleRatchet:
    def __init__(self, shared_secret):
        self.shared_secret = shared_secret
        self.eph_private_key = hashlib.sha256(self.shared_secret).digest()[:32]
        self.eph_public_key = hashlib.sha256(self.eph_private_key).digest()
        self.chain_key = self._hkdf_expand(self.shared_secret, b"chain_key")
        self.message_keys = {}

    def _hkdf_expand(self, key_material, info):
        """Виконує HKDF для розширення ключового матеріалу."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        )
        return hkdf.derive(key_material)

    def update_keys(self):
        """Оновлює кореневий та ланцюговий ключ."""
        logger.info("Оновлення ключів Double Ratchet...")
        new_root_key = self._hkdf_expand(self.chain_key, b"root_key_update")
        new_chain_key = self._hkdf_expand(new_root_key, b"chain_key")
        self.chain_key = new_chain_key
        logger.debug(f"Новий root_key: {new_root_key.hex()}")
        logger.debug(f"Новий chain_key: {self.chain_key.hex()}")

    def encrypt(self, message):
        """Шифрує повідомлення за допомогою ChaCha20."""
        logger.info("Шифрування повідомлення...")
        nonce = os.urandom(16)  # Генеруємо унікальний nonce з довжиною 16 байт

        cipher = Cipher(algorithms.ChaCha20(self.chain_key, nonce), mode=None)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

        # Оновлюємо ключі після шифрування
        self.update_keys()

        logger.debug(f"Nonce: {nonce.hex()}")
        logger.debug(f"Зашифроване повідомлення: {ciphertext.hex()}")

        return ciphertext, nonce, self.eph_public_key

    def decrypt(self, ciphertext, nonce):
        """Дешифрує повідомлення за допомогою ChaCha20."""
        logger.info("Дешифрування повідомлення...")

        cipher = Cipher(algorithms.ChaCha20(self.chain_key, nonce), mode=None)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Оновлюємо ключі після дешифрування
        self.update_keys()

        logger.debug(f"Розшифроване повідомлення: {plaintext.decode('utf-8', errors='ignore')}")
        return plaintext.decode("utf-8", errors="ignore")

    def receive_ratchet(self, new_public_key):
        """Оновлює ключі на основі нового публічного ключа Діффі-Хеллмана."""
        logger.info("Оновлення ключів на основі отриманого публічного ключа...")
        combined_key = hashlib.sha256(self.eph_private_key + new_public_key).digest()
        self.chain_key = self._hkdf_expand(combined_key, b"chain_key_update")
        logger.debug(f"Новий chain_key після рачета: {self.chain_key.hex()}")
