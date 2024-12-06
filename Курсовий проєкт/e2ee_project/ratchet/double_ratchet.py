import logging
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Налаштування логування
logger = logging.getLogger("double_ratchet")
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('app.log')
console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

class DoubleRatchet:
    def __init__(self, private_key, peer_public_key, client_id):
        self.client_id = client_id
        self.private_key = private_key
        self.peer_public_key = peer_public_key
        logger.info(f"{self.client_id} - Ініціалізація Double Ratchet для клієнта...")
        self.shared_secret = self._derive_shared_secret()
        self.root_key = self.shared_secret  # Початковий root_key
        self.chain_key = self._hkdf_expand(self.root_key, b"chain_key")  # Початковий chain_key

    def _derive_shared_secret(self):
        logger.debug(f"{self.client_id} - Розрахунок спільного секрету...")
        shared_secret = self.private_key.exchange(self.peer_public_key)
        logger.info(f"{self.client_id} - Спільний секрет успішно розраховано: {shared_secret.hex()}")
        return shared_secret

    def _hkdf_expand(self, key_material, info):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        )
        return hkdf.derive(key_material)

    def _update_keys(self):
        logger.info(f"{self.client_id} - Оновлення ключів...")
        # Оновлюємо кореневий ключ та отримуємо новий ланцюговий ключ
        new_root_key = self._hkdf_expand(self.root_key, b"root_key_update")
        new_chain_key = self._hkdf_expand(new_root_key, b"chain_key")
        self.root_key = new_root_key
        self.chain_key = new_chain_key
        logger.debug(f"{self.client_id} - Новий root_key: {self.root_key.hex()}")
        logger.debug(f"{self.client_id} - Новий chain_key: {self.chain_key.hex()}")

    def encrypt(self, plaintext):
        """
        Шифрує повідомлення.

        :param plaintext: Текст повідомлення (bytes).
        :return: Зашифроване повідомлення (bytes).
        """
        nonce = os.urandom(16)  # Унікальний одноразовий вектор ініціалізації для ChaCha20
        cipher = Cipher(algorithms.ChaCha20(self.chain_key, nonce), mode=None)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        logger.info(f"Шифрування для клієнта {self.client_id}")
        logger.debug(f"Nonce: {nonce.hex()}")
        logger.debug(f"Зашифроване повідомлення: {ciphertext.hex()}")
        return nonce + ciphertext

    def decrypt(self, ciphertext):
        """
        Дешифрує повідомлення.

        :param ciphertext: Зашифроване повідомлення (bytes).
        :return: Розшифроване повідомлення (bytes).
        """
        nonce = ciphertext[:16]  # Перші 16 байт — це nonce
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.ChaCha20(self.chain_key, nonce), mode=None)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        logger.info(f"Дешифрування для клієнта {self.client_id}")
        logger.debug(f"Розшифроване повідомлення: {plaintext.decode(errors='ignore')}")
        return plaintext
