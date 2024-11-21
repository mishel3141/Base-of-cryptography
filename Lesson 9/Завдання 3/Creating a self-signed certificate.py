#   Код робить:
#      1. Завантажує раніше згенерований приватний ключ клієнта.
#      2. Використовує приватний ключ для підписання сертифіката.
#      3. Створює сертифікат із терміном дії 1 рік.
#      4. Зберігає сертифікат у файл client.crt.
#      5. Перевіряє сертифікат:
#           - вміст сертифіката виводиться в текстовому форматі PEM;
#           - структура сертифіката (об'єкт cryptography.x509.Certificate) виводиться для аналізу.
#

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

# Завантаження приватного ключа
with open("client.key", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

# Створення самопідписаного сертифіката
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),             # Країна
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Kyiv"),          # Місто
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Robot_dreams"),  # Організація
    x509.NameAttribute(NameOID.COMMON_NAME, "www.robotdreams.cc"),  # Домен
    x509.NameAttribute(NameOID.EMAIL_ADDRESS, "youremail@example.com")  # Email
])

certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))  # Сертифікат дійсний 1 рік
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(private_key, hashes.SHA256())
)

# Збереження сертифікату у файл
with open("client.crt", "wb") as cert_file:
    cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

print("Самопідписаний сертифікат збережено у 'client.crt'")

# Перевірка вмісту сертифіката
print("\nВміст сертифіката:")
print(certificate.public_bytes(serialization.Encoding.PEM).decode())

# Перевірка структури сертифіката
print("\nСтруктура сертифіката ASN.1:")
print(certificate)

