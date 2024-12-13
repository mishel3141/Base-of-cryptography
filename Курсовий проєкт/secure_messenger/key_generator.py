import os
import sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# Функція для генерації ключів
def generate_keys_for_user(username):
    # Створення каталогу для користувача, якщо не існує
    user_dir = os.path.join(os.getcwd(), username)
    os.makedirs(user_dir, exist_ok=True)
    
    # Генерація ключів Ed25519 (підпис)
    ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
    ed25519_public_key = ed25519_private_key.public_key()

    # Генерація ключів X25519 (шифрування)
    x25519_private_key = x25519.X25519PrivateKey.generate()
    x25519_public_key = x25519_private_key.public_key()

    # Збереження приватного ключа Ed25519 в файл (формат PKCS8)
    with open(os.path.join(user_dir, f"{username}_ed25519_private_key.pem"), "wb") as f:
        f.write(ed25519_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Збереження публічного ключа Ed25519 в файл
    with open(os.path.join(user_dir, f"{username}_ed25519_public_key.pem"), "wb") as f:
        f.write(ed25519_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Збереження приватного ключа X25519 в файл (формат PKCS8)
    with open(os.path.join(user_dir, f"{username}_x25519_private_key.pem"), "wb") as f:
        f.write(x25519_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Збереження публічного ключа X25519 в файл
    with open(os.path.join(user_dir, f"{username}_x25519_public_key.pem"), "wb") as f:
        f.write(x25519_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Ключі для {username} успішно згенеровано та збережено в каталозі {user_dir}")

# Основна частина
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Використання: py key_generator.py <ім'я користувача>")
        sys.exit(1)

    username = sys.argv[1]
    generate_keys_for_user(username)
