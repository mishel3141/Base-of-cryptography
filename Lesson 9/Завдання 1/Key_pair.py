#   Програмний код виконує наступні дії:
#
#   1. Генерація ключової пари:   - приватний ключ, який зберігається у файлі server.key;
#                                 - публічний ключ, який зберігається у файлі server.pub.
#
#   2. Вивід структури приватного ключа.
#
#   3. Перевірку публічного ключа (використовується команда OpenSSL: openssl rsa -pubout -in server.key).
#
#

import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# 1. Генерація приватного ключа RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,  # стандартний публічний експонент
    key_size=2048           # довжина ключа
)

# Збереження приватного ключа у форматі PEM
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()  # без паролю
)

# Запис приватного ключа у файл
with open("server.key", "wb") as private_file:
    private_file.write(private_pem)

# Отримання публічного ключа з приватного ключа
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Збереження публічного ключа у файл
with open("server.pub", "wb") as public_file:
    public_file.write(public_pem)


# 2. Cтруктура приватного ключа

# Виведення приватного ключа у форматі PEM
print("\n=== Приватний ключ RSA ===")
print(private_pem.decode("utf-8"))

# Витягання числових параметрів ключа
private_numbers = private_key.private_numbers()

# Виведення структури приватного ключа
print("Структура та вміст приватного ключа RSA:")
print(f"Модуль (n): {private_numbers.public_numbers.n}")
print(f"Публічна експонента (e): {private_numbers.public_numbers.e}")
print(f"Приватна експонента (d): {private_numbers.d}")
print(f"Простий множник p: {private_numbers.p}")
print(f"Простий множник q: {private_numbers.q}")
print(f"Експонента dP: {private_numbers.dmp1}")
print(f"Експонента dQ: {private_numbers.dmq1}")
print(f"Коефіцієнт обернення (qInv): {private_numbers.iqmp}")


# 3. Перевірка публічного ключа за допомогою OpenSSL
print("\n=== Публічний ключ RSA ===")
try:
    result_pub = subprocess.run(
        ["openssl", "rsa", "-pubout", "-in", "server.key"],
        capture_output=True,
        text=True
    )
    print(result_pub.stdout)  # Виведення публічного ключа
except FileNotFoundError:
    print("OpenSSL не встановлений на вашій системі. Перевірте наявність OpenSSL.")
