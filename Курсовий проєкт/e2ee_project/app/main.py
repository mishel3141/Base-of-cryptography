from app.key_management import KeyManagement
from app.double_ratchet import DoubleRatchet
from app.encryption import encrypt_data, decrypt_data
from app.config import logger

# Приклад ініціалізації та використання всіх компонентів

def main():
    # Ініціалізація керування ключами
    client_1 = KeyManagement(client_id="client_1")
    client_2 = KeyManagement(client_id="client_2")

    # Генерація спільного секрету
    shared_secret = client_1.derive_shared_secret(client_2.get_public_key_bytes())

    # Ініціалізація Double Ratchet
    ratchet_1 = DoubleRatchet(shared_secret)
    ratchet_2 = DoubleRatchet(shared_secret)

    # Генерація ключів для Double Ratchet
    ratchet_1.generate_ratchet_keys()
    ratchet_2.generate_ratchet_keys()

    # Шифрування та дешифрування повідомлення
    message = "Привіт, це секретне повідомлення!"
    encrypted_msg = ratchet_1.encrypt_message(message)
    decrypted_msg = ratchet_2.decrypt_message(encrypted_msg)

    logger.info(f"Оригінальне повідомлення: {message}")
    logger.info(f"Зашифроване повідомлення: {encrypted_msg.hex()}")
    logger.info(f"Розшифроване повідомлення: {decrypted_msg.decode()}")

if __name__ == "__main
