#   Код автентифікованого протоколу узгодження ключів Діффі-Хеллмана на еліптичних кривих
#         з використанням алгоритму ECDSA для електронного цифрового підпису
#

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from binascii import hexlify, unhexlify

# Завантажуємо відкритий ключ Alice для підпису (довгостроковий)
alice_pub_sign_key_raw = b"""
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAES/35y89DRx2XEh6pJvCckadQ9Awuys84
HORPVVaDksVxWfSkngYrz/c+HwVS9tV5ivnVwCHxyJ8gTQob/0LDDg==
-----END PUBLIC KEY-----
"""
alice_pub_sign_key = serialization.load_pem_public_key(alice_pub_sign_key_raw)

# Відкритий ключ Alice для ECDH та його підпис
alice_x_pub_key = b'92ce3bc6d941238da92639c72a7d3bb483d3c18fdca9f42164459a3751638433'
signature = b'3045022034b7944bf92bfaa2791b5fe929d915add4ee59dbd9e776c1520568fbf2503048022100f09c9113f38fadb33b05332eab9a4982f7dda35fb1f503bb46da806c8e8dbaa2'

# 1. Генеруємо довгострокову ключову пару Боба для підпису
bob_sign_key = ec.generate_private_key(ec.SECP256K1())
bob_sign_pub_key = bob_sign_key.public_key()

# Зберігаємо відкритий ключ підпису Боба у форматі PEM
bob_sign_pub_pem = bob_sign_pub_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print("Bob's signing public key (PEM):\n\n", bob_sign_pub_pem.decode())

# 2. Генеруємо приватний ключ для ECDH
bob_ecdh_key = x25519.X25519PrivateKey.generate()
bob_ecdh_pub_key = bob_ecdh_key.public_key()
bob_y_pub_hex = hexlify(bob_ecdh_pub_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
))
print("Bob's ECDH public key (hex):", bob_y_pub_hex.decode())

# 3. Перевіряємо підпис відкритого ключа Alice
try:
    alice_pub_sign_key.verify(
        unhexlify(signature),
        unhexlify(alice_x_pub_key),
        ec.ECDSA(hashes.SHA256())
    )
    print("\nAlice's signature is valid.")
except InvalidSignature:
    print("\nAlice's signature is invalid!")
    exit()

# 4. Створюємо підпис для відкритого ключа ECDH
bob_signature = bob_sign_key.sign(
    bob_ecdh_pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ),
    ec.ECDSA(hashes.SHA256())
)
bob_signature_hex = hexlify(bob_signature)
print("\nBob's ECDH key signature (hex):", bob_signature_hex.decode())
