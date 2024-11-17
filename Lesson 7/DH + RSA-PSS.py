#   Реалізація автентифікованого протоколу Діффі-Хеллмана з використанням схеми RSA-PSS для підпису.

#  Основні кроки коду:
#     1. Генерація загальних параметрів DH
#     2. Генерація приватних і публічних ключів Аліси та Боба як для DH, так і для RSA.
#     3. Веріфікація підписів: кожна сторона перевіряє, що отриманий публічний ключ було підписано іншою стороною.
#     4. Порівняння Derived Key: обидві сторони порівнюють Derived Key, щоб переконатися, що вони співпадають.


from binascii import hexlify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
    load_pem_private_key,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#     Крок 1:  Генерація загальних параметрів DH
print("STEP 1:  Common DH parameters")

parameters = dh.generate_parameters(generator=2, key_size=2048)
print("Module = ", parameters.parameter_numbers().p)
print("Gen = ", parameters.parameter_numbers().g)

#     Крок 2:  Генерація приватних і публічних ключів Аліси та Боба як для DH, так і для RSA (у форматі DER)
print("\n\nSTEP 2:  Key generation for DH and RSA")

# ---------------------- ALICE ----------------------
print("\n--- Alice's side ---")

# Генерація DH ключів для Alice
alice_private_key = parameters.generate_private_key()
alice_public_key = alice_private_key.public_key()

print("\nAlice's DH Private Key:")
print(hexlify(alice_private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())))
print("Alice's DH Public Key:")
print(hexlify(alice_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)))

# Генерація RSA ключів для підпису Аліси
alice_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
alice_rsa_public_key = alice_rsa_private_key.public_key()

print("\nAlice's RSA Private Key:")
print(hexlify(alice_rsa_private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())))
print("Alice's RSA Public Key:")
print(hexlify(alice_rsa_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)))

# Аліса підписує публічний ключ DH
alice_signature = alice_rsa_private_key.sign(
    alice_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("\nAlice's Public Key Signature:\n", hexlify(alice_signature))

# ---------------------- BOB ----------------------
print("\n--- Bob's side ---")

# Генерація ключів DH для Bob
bob_private_key = parameters.generate_private_key()
bob_public_key = bob_private_key.public_key()

print("\nBob's DH Private Key:")
print(hexlify(bob_private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())))
print("Bob's DH Public Key:")
print(hexlify(bob_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)))

# Генерація ключів RSA для підпису
bob_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
bob_rsa_public_key = bob_rsa_private_key.public_key()

print("\nBob's RSA Private Key:")
print(hexlify(bob_rsa_private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())))
print("Bob's RSA Public Key:")
print(hexlify(bob_rsa_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)))

# Боб підписує публічний ключ DH
bob_signature = bob_rsa_private_key.sign(
    bob_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("\nBob's Public Key Signature:\n", hexlify(bob_signature))

#     Крок 3:   Веріфікація підписів на кожній стороні
print("\n\nSTEP 3:  Signature verification")

# ----------- Аліса отримує публічний ключ Боба ----------
print("\n--- Аліса отримує публічний ключ Боба ---")
bob_public_key_bytes = bob_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

# Верифікація підпису Боба
try:
    bob_rsa_public_key.verify(
        bob_signature,
        bob_public_key_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Bob's signature verified!")
except Exception as e:
    print(f"Bob's signature failed verification: {e}")

# ------------ Bob отримує публічний ключ Alice ----------------
print("\n--- Боб отримує публічний ключ Аліси ---")
alice_public_key_bytes = alice_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

# Верифікація підпису Аліси
try:
    alice_rsa_public_key.verify(
        alice_signature,
        alice_public_key_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Alice's signature verified!")
except Exception as e:
    print(f"Alice's signature failed verification: {e}")

#     Крок 4. Порівняння Derived Key на кожній стороні, щоб переконатися, що вони співпадають
print("\n\nSTEP 4: Derived Key Comparison")

# Обчислення спільного секрету та виведення Derived Key
alice_shared_value = alice_private_key.exchange(bob_public_key)
bob_shared_value = bob_private_key.exchange(alice_public_key)

alice_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data"
).derive(alice_shared_value)

bob_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data"
).derive(bob_shared_value)

print("\nAlice's Derived Key = ", hexlify(alice_derived_key))
print("Bob's Derived Key   = ", hexlify(bob_derived_key))

print("\nShared values equal?\t", alice_shared_value == bob_shared_value)
print("Shared keys equal?\t", alice_derived_key == bob_derived_key)
