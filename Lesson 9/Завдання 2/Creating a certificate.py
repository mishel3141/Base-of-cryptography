#   Даний код:
#   1.Генерує ключову пару RSA і зберігає приватний ключ у файлі client.key.
#   2. Створює CSR із наступними атрибутами:
#     - Country Name (C) — країна;
#     - Locality Name (L) — місто;
#     - Organization Name (O) — організація;
#     - Common Name (CN) — домен;
#     - Email Address — електронна пошта власника.
#   3. Зберігає CSR у файл client.csr.
#

from cryptography import x509
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import (
    CertificateSigningRequestBuilder, NameOID, Name
)
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.hashes import SHA256

# 1. Генерація ключової пари RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Збереження приватного ключа у файл (PEM формат)
with open("client.key", "wb") as key_file:
    key_file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# 2. Створення запиту на сертифікат (CSR)
csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),             # Країна
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Kyiv"),          # Місто
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Robot_dreams"),  # Організація
    x509.NameAttribute(NameOID.COMMON_NAME, "www.robotdreams.cc"),  # Домен
    x509.NameAttribute(NameOID.EMAIL_ADDRESS, "youremail@example.com")  # Email
]))
csr = csr_builder.sign(private_key, SHA256())

# Збереження CSR у файл (PEM формат)
with open("client.csr", "wb") as csr_file:
    csr_file.write(csr.public_bytes(serialization.Encoding.PEM))

print("CSR збережено у 'client.csr'")