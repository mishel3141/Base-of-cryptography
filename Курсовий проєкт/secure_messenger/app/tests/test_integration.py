
import os
from app.double_ratchet import DoubleRatchet
from app.utilities import encrypt_message, decrypt_message, generate_key_pair, derive_shared_secret

def integration_test():
    print("Запуск інтеграційного тесту...")
    
    # Ініціалізація Double Ratchet
    root_key = os.urandom(32)
    alice_ratchet = DoubleRatchet(root_key)
    bob_ratchet = DoubleRatchet(root_key)
    
    # Генерація ключів
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()
    
    # Обмін ключами та генерація спільного секрету
    alice_shared_secret = derive_shared_secret(alice_private, bob_public)
    bob_shared_secret = derive_shared_secret(bob_private, alice_public)
    assert alice_shared_secret == bob_shared_secret, "Обмін ключами провалився!"
    
    # Шифрування/дешифрування
    message = "Привіт, це інтеграційний тест!"
    message_id = b"1"
    encrypted_packet = alice_ratchet.encrypt(message, message_id)
    decrypted_message = bob_ratchet.decrypt(encrypted_packet)
    assert decrypted_message == message, "Шифрування/дешифрування провалилося!"
    
    print("Інтеграційний тест пройдено успішно.")

if __name__ == "__main__":
    integration_test()
