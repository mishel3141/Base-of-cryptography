import os
from app.utilities import encrypt_message, decrypt_message

def test_encryption():
    shared_secret = os.urandom(32)
    message = "Тестове повідомлення"
    message_id = b"123456"
    ciphertext, nonce, signature = encrypt_message(shared_secret, message, message_id)
    decrypted_message = decrypt_message(shared_secret, ciphertext, nonce, signature)
    assert decrypted_message == message, "Шифрування/дешифрування не працює!"
    print("Тест шифрування/дешифрування пройдено.")

def test_encryption_with_wrong_key():
    shared_secret = os.urandom(32)
    wrong_key = os.urandom(32)
    message = "Тестове повідомлення"
    message_id = b"123456"
    ciphertext, nonce, signature = encrypt_message(shared_secret, message, message_id)
    try:
        decrypt_message(wrong_key, ciphertext, nonce, signature)
        assert False, "Дешифрування повинно було провалитися з невірним ключем."
    except Exception:
        print("Тест із неправильним ключем пройдено.")

if __name__ == "__main__":
    test_encryption()
    test_encryption_with_wrong_key()
