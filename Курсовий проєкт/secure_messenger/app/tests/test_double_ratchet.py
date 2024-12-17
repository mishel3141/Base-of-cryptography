import os
from app.double_ratchet import DoubleRatchet

def test_double_ratchet_initialization():
    root_key = os.urandom(32)
    ratchet = DoubleRatchet(root_key)
    assert len(ratchet.root_key) == 32, "Кореневий ключ має бути довжиною 32 байти."
    assert len(ratchet.send_chain_key) == 32, "Ланцюговий ключ для відправлення має бути довжиною 32 байти."
    assert len(ratchet.receive_chain_key) == 32, "Ланцюговий ключ для отримання має бути довжиною 32 байти."
    print("Тест ініціалізації Double Ratchet пройдено.")

def test_ratchet_step():
    root_key = os.urandom(32)
    shared_secret = os.urandom(32)
    ratchet = DoubleRatchet(root_key)
    initial_root_key = ratchet.root_key
    ratchet.ratchet_step(shared_secret)
    assert ratchet.root_key != initial_root_key, "Кореневий ключ повинен змінюватися після Ratchet Step."
    assert len(ratchet.send_chain_key) == 32, "Новий send_chain_key має бути довжиною 32 байти."
    assert len(ratchet.receive_chain_key) == 32, "Новий receive_chain_key має бути довжиною 32 байти."
    print("Тест Ratchet Step пройдено.")

def test_encryption_decryption():
    root_key = os.urandom(32)
    ratchet = DoubleRatchet(root_key)
    message = "Тестове повідомлення"
    message_id = b"123456"
    encrypted_packet = ratchet.encrypt(message, message_id)
    decrypted_message = ratchet.decrypt(encrypted_packet)
    assert decrypted_message == message, "Дешифроване повідомлення має співпадати з оригінальним."
    print("Тест шифрування/дешифрування пройдено.")

def test_unique_message_keys():
    root_key = os.urandom(32)
    ratchet = DoubleRatchet(root_key)
    keys = set()
    for _ in range(10):
        message_key, next_chain_key = ratchet.generate_message_key(ratchet.send_chain_key)
        keys.add(message_key)
        ratchet.send_chain_key = next_chain_key
    assert len(keys) == 10, "Кожен ключ повідомлення має бути унікальним."
    print("Тест унікальних ключів повідомлень пройдено.")

def run_double_ratchet_tests():
    print("Запуск тестів для Double Ratchet...")
    test_double_ratchet_initialization()
    test_ratchet_step()
    test_encryption_decryption()
    test_unique_message_keys()
    print("Усі тести для Double Ratchet пройдено успішно.")

if __name__ == "__main__":
    run_double_ratchet_tests()
