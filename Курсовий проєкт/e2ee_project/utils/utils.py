import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_private_key():
    """
    Генерує новий приватний ключ для використання в схемах криптографії.
    """
    private_key = x25519.X25519PrivateKey.generate()
    return private_key

def generate_public_key_from_private(private_key):
    """
    Генерує публічний ключ на основі приватного ключа.
    
    :param private_key: Приватний ключ (x25519.X25519PrivateKey)
    :return: Публічний ключ (x25519.X25519PublicKey)
    """
    return private_key.public_key()

def save_private_key_to_file(private_key, file_path):
    """
    Зберігає приватний ключ у файл у форматі PEM.
    
    :param private_key: Приватний ключ (x25519.X25519PrivateKey)
    :param file_path: Шлях до файлу для збереження
    """
    pem_data = private_key_to_pem(private_key)
    with open(file_path, 'wb') as pem_file:
        pem_file.write(pem_data)

def save_public_key_to_file(public_key, file_path):
    """
    Зберігає публічний ключ у файл у форматі PEM.
    
    :param public_key: Публічний ключ (x25519.X25519PublicKey)
    :param file_path: Шлях до файлу для збереження
    """
    pem_data = public_key_to_pem(public_key)
    with open(file_path, 'wb') as pem_file:
        pem_file.write(pem_data)

def load_private_key_from_pem(pem_data):
    """
    Завантажує приватний ключ з PEM-формату.
    
    :param pem_data: PEM-дані приватного ключа (bytes)
    :return: Приватний ключ (x25519.X25519PrivateKey)
    """
    return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())

def load_public_key_from_pem(pem_data):
    """
    Завантажує публічний ключ з PEM-формату.
    
    :param pem_data: PEM-дані публічного ключа (bytes)
    :return: Публічний ключ (x25519.X25519PublicKey)
    """
    return serialization.load_pem_public_key(pem_data, backend=default_backend())

def private_key_to_pem(private_key):
    """
    Конвертує приватний ключ в PEM-формат.
    
    :param private_key: Приватний ключ (x25519.X25519PrivateKey)
    :return: PEM-дані приватного ключа (bytes)
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def public_key_to_pem(public_key):
    """
    Конвертує публічний ключ в PEM-формат.
    
    :param public_key: Публічний ключ (x25519.X25519PublicKey)
    :return: PEM-дані публічного ключа (bytes)
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def derive_shared_secret(private_key, peer_public_key):
    """
    Виводить спільний секрет на основі приватного та публічного ключа.
    
    :param private_key: Приватний ключ (x25519.X25519PrivateKey)
    :param peer_public_key: Публічний ключ партнера (x25519.X25519PublicKey)
    :return: Спільний секрет (bytes)
    """
    return private_key.exchange(x25519.X25519PrivateKey(), peer_public_key)

def generate_nonce():
    """
    Генерує випадковий nonce для використання в шифруванні.
    :return: nonce (bytes)
    """
    return os.urandom(12)

def hash_data(data):
    """
    Хешує дані з використанням SHA256.
    
    :param data: Дані для хешування (bytes)
    :return: Хеш (bytes)
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()
