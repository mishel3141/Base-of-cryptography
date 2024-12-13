# app/encryption.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
import os
import logging

def encrypt(self, message):
    """Шифрує повідомлення за допомогою ChaCha20-Poly1305."""
    logger.info("Шифрування повідомлення...")
    key = self.chain_key  # Використовуємо chain_key як ключ шифрування
    nonce = os.urandom(12)  # Генеруємо унікальний nonce (12 байт для ChaCha20-Poly1305)

    # Ініціалізація ChaCha20-Poly1305
    chacha = ChaCha20Poly1305(key)

    # Шифруємо повідомлення (результат включає MAC)
    ciphertext = chacha.encrypt(nonce, message.encode(), None)

    # Оновлюємо ключі після шифрування
    self.update_keys()

    logger.debug(f"Nonce: {nonce.hex()}")
    logger.debug(f"Зашифроване повідомлення (з MAC): {ciphertext.hex()}")

    return ciphertext, nonce, self.eph_public_key

def decrypt(self, ciphertext, nonce):
    """Дешифрує повідомлення за допомогою ChaCha20-Poly1305."""
    logger.info("Дешифрування повідомлення...")
    key = self.chain_key  # Використовуємо chain_key як ключ дешифрування

    # Ініціалізація ChaCha20-Poly1305
    chacha = ChaCha20Poly1305(key)

    try:
        # Дешифруємо повідомлення
        plaintext = chacha.decrypt(nonce, ciphertext, None)

        # Оновлюємо ключі після дешифрування
        self.update_keys()

        logger.debug(f"Розшифроване повідомлення: {plaintext.decode('utf-8')}")
        return plaintext.decode("utf-8")
    except Exception as e:
        logger.error(f"Помилка при дешифруванні: {e}")
        return None

