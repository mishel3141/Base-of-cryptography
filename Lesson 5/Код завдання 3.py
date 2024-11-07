# 
# 1. Сіль (salt) генерується один раз для кожного користувача та зберігається в JSON файлі.
#    Якщо користувач уже існує, сіль для нього завантажується з файлу. Якщо користувача немає
#    в файлі або файл не існує, створюється новий запис для цього користувача.
# 2. PBKDF2: Сіль передається разом із паролем для хешування. Вона використовується, щоб з
#    кожним паролем генерувати різні результати навіть за однакових паролів, що робить систему
#    стійкою до атак типу "rainbow tables".
# 3.	Файл метаданих: Всі дані, включаючи сіль, зберігаються в текстовому файлі у форматі JSON.
#     Це дозволяє зберігати необхідні метадані для кожного користувача, такі як сіль.
#     JSON-файл:
#        [
#          {
#             "username": "John Doe",
#             "salt": "75b777fc8f70045c6006b39da1b3d622"
#           }
#         ]
#

import json
import os
import hashlib
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Шлях до файлу з метаданими
METADATA_FILE = "user_metadata.json"


# Функція для завантаження метаданих
def load_metadata():
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "r") as file:
            return json.load(file)
    return []


# Функція для збереження метаданих
def save_metadata(metadata):
    with open(METADATA_FILE, "w") as file:
        json.dump(metadata, file, indent=4)


# Функція для пошуку користувача в метаданих
def find_user_metadata(username):
    metadata = load_metadata()
    for entry in metadata:
        if entry["username"] == username:
            return entry
    return None


# Функція для створення або отримання солі для користувача
def get_or_generate_salt(username):
    user_metadata = find_user_metadata(username)
    if user_metadata:
        return b64decode(user_metadata["salt"])

    # Генеруємо нову сіль
    salt = os.urandom(16)  # 128-бітна сіль
    new_entry = {
        "username": username,
        "salt": b64encode(salt).decode()
    }

    metadata = load_metadata()
    metadata.append(new_entry)
    save_metadata(metadata)

    return salt


# Основна функція для створення ключа
def derive_key(username, password):
    salt = get_or_generate_salt(username)

    # Налаштовуємо PBKDF2 з SHA-256 для генерації ключа
    # Параметри:
    #    salt: Унікальна сіль для кожного користувача
    #    dkLen=16: Генеруємо 16-байтний (128 біт) ключ для AES-128
    #    count=1000000: Кількість ітерацій для PBKDF2. Більше ітерацій робить процес довшим, що ускладнює атаки брутфорсом.
    #
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,  # AES-128 потребує 128 біт, тобто 16 байт
        salt=salt,
        iterations=100000,  # Рекомендована кількість ітерацій
        backend=default_backend()
    )

    key = kdf.derive(password.encode())  # Генеруємо ключ
    return key


# Тестування функції
if __name__ == "__main__":
    username = "John Doe"
    password = "securepassword123"

    key = derive_key(username, password)
    print(f"Generated key for {username}: {key.hex()}")
