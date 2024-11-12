from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Завантаження відкритого ключа з файлу
with open("task_pub.pem", "rb") as key_file:
    public_key = load_pem_public_key(key_file.read())

# Введення повідомлення через input
message = input("Введіть повідомлення для шифрування: ").encode('utf-8')

# Шифрування повідомлення
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Збереження шифротексту у форматі hex
with open("task-2-message.txt", "w") as encrypted_file:
    encrypted_file.write(ciphertext.hex())

print("Повідомлення зашифровано та збережено у task-2-message.txt")