from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import sys

# Завантаження відкритого ключа
with open("task_pub.pem", "rb") as pub_key_file:
    public_key = load_pem_public_key(pub_key_file.read())

# Завантаження повідомлення
with open("task_message.txt", "r") as msg_file:
    message = bytes.fromhex(msg_file.read().strip())

# Завантаження підпису
with open("task_signature.txt", "r") as sig_file:
    signature = bytes.fromhex(sig_file.read().strip())

try:
    # Перевірка підпису
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Підпис верифікований успішно.")
except Exception as e:
    print("Помилка верифікації підпису:", e)