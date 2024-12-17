from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import logging

def encrypt_data(key, data):
    """Шифрування даних за допомогою алгоритму ChaCha."""
    nonce = os.urandom(16)  # Генерація випадкового "nonce"
    cipher = Cipher(algorithms.ChaCha20(key, nonce), modes.POLY1305(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    logging.info(f"Encryption successful")
    return nonce + ciphertext

def decrypt_data(key, encrypted_data):
    """Розшифрування даних за допомогою алгоритму ChaCha."""
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.ChaCha20(key, nonce), modes.POLY1305(), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    logging.info(f"Decryption successful")
    return plaintext.decode()
	