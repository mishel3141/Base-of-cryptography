import os
from utils import generate_private_key, private_key_to_pem, public_key_to_pem, save_private_key_to_file, save_public_key_to_file

# Шлях до папки для збереження ключів
KEYS_DIR = "keys"

def ensure_keys_directory():
    """
    Перевіряє існування папки keys і створює її, якщо вона не існує.
    """
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
        print(f"Директорія {KEYS_DIR} створена.")

def generate_and_save_keys(identity):
    """
    Генерує приватний та публічний ключі і зберігає їх у файли.
    
    :param identity: Ідентифікатор (Alice або Bob)
    """
    private_key = generate_private_key()
    public_key = private_key.public_key()

    private_key_file = os.path.join(KEYS_DIR, f"{identity.lower()}_key.pem")
    public_key_file = os.path.join(KEYS_DIR, f"{identity.lower()}_public_key.pem")

    # Збереження ключів у файли
    save_private_key_to_file(private_key, private_key_file)
    save_public_key_to_file(public_key, public_key_file)

    print(f"Ключі для {identity} збережено:\n  Приватний: {private_key_file}\n  Публічний: {public_key_file}")

if __name__ == "__main__":
    ensure_keys_directory()
    generate_and_save_keys("Alice")
    generate_and_save_keys("Bob")
