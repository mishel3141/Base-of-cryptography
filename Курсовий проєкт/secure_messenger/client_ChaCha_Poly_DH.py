import socket
import threading
import logging
import json
import sys
import base64
import os
from colorama import Fore, Style, init
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# Ініціалізація colorama
init()

# Налаштування логування
logging.basicConfig(
    filename='logs/client.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

HOST = '127.0.0.1'
PORT = 12345

class DHClient:
    """Клас для обміну DH-ключами та обчислення спільного ключа."""
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.shared_key = None

    def generate_shared_key(self, peer_public_bytes):
        """Обчислює спільний ключ на основі отриманого публічного ключа."""
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = self.private_key.exchange(peer_public_key)
        print(f"{Fore.CYAN}Спільний ключ обчислено: {shared_secret.hex()[:32]}{Style.RESET_ALL}")
        return shared_secret[:32]

def encrypt_message(message: str, key: bytes) -> dict:
    """Шифрування повідомлення за допомогою ChaCha20-Poly1305."""
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, message.encode(), None)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }

def decrypt_message(data: dict, key: bytes) -> str:
    """Розшифрування повідомлення за допомогою ChaCha20-Poly1305."""
    chacha = ChaCha20Poly1305(key)
    nonce = base64.b64decode(data['nonce'])
    ciphertext = base64.b64decode(data['ciphertext'])
    return chacha.decrypt(nonce, ciphertext, None).decode()

def receive_messages(client_socket, dh_client):
    """Слухати та обробляти вхідні повідомлення."""
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                print(f"{Fore.LIGHTBLACK_EX}З'єднання з сервером розірвано.{Style.RESET_ALL}")
                break

            message_data = json.loads(data.decode())

            # Логування отриманих даних для діагностики
            logging.info(f"Отримано дані: {message_data}")

            # Перевірка на DH-публічний ключ
            if "dh_public" in message_data:
                peer_name = message_data.get("peer_name", "Невідомий")
                peer_public = base64.b64decode(message_data["dh_public"])
                dh_client.shared_key = dh_client.generate_shared_key(peer_public)
                print(f"{Fore.YELLOW}Спільний ключ з {peer_name} успішно узгоджено.{Style.RESET_ALL}")
                logging.info(f"Спільний ключ з {peer_name} успішно узгоджено.")

            # Обробка зашифрованого повідомлення
            elif "message" in message_data:
                sender = message_data.get("sender", "Невідомий")
                encrypted_message = message_data.get("message", {})
                if dh_client.shared_key:
                    decrypted_message = decrypt_message(encrypted_message, dh_client.shared_key)
                    print(f"{Fore.RED}<<<< {sender}: {decrypted_message}{Style.RESET_ALL}")
                    logging.info(f"Отримано повідомлення від {sender}: {decrypted_message}")
                else:
                    print(f"{Fore.YELLOW}Отримано повідомлення, але ключ не узгоджено.{Style.RESET_ALL}")
            else:
                logging.warning("Отримано невідомий тип даних.")
        except ConnectionResetError:
            print(f"{Fore.RED}Сервер примусово розірвав з'єднання.{Style.RESET_ALL}")
            logging.error("Сервер примусово розірвав з'єднання.")
            break
        except Exception as e:
            logging.error(f"Помилка при отриманні: {e}")
            break

def start_client():
    """Підключення до сервера та обробка відправки/отримання повідомлень."""
    if len(sys.argv) != 3:
        print(f"{Fore.YELLOW}Використання: python client.py <Ваше_ім'я> <Ім'я_співрозмовника>{Style.RESET_ALL}")
        sys.exit(1)

    sender_name, receiver_name = sys.argv[1], sys.argv[2]
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    # Ініціалізація DH-клієнта
    dh_client = DHClient()
    print(f"{Fore.GREEN}Підключено до сервера як {sender_name}.{Style.RESET_ALL}")

    # Надсилаємо ім'я і DH-публічний ключ серверу
    client_socket.send(json.dumps({
        "name": sender_name,
        "dh_public": base64.b64encode(dh_client.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )).decode()
    }).encode())

    threading.Thread(target=receive_messages, args=(client_socket, dh_client), daemon=True).start()

    # Відправка повідомлень
    while True:
        message = input(">>> ")
        if message.lower() == "exit":
            print(f"{Fore.LIGHTBLACK_EX}Вихід з чату.{Style.RESET_ALL}")
            logging.info("Клієнт завершив роботу.")
            break

        if not dh_client.shared_key:
            print(f"{Fore.YELLOW}Сесійний ключ ще не узгоджено. Очікуйте...{Style.RESET_ALL}")
            continue

        try:
            encrypted_message = encrypt_message(message, dh_client.shared_key)
            client_socket.send(json.dumps({
                "message": encrypted_message,
                "receiver": receiver_name
            }).encode())
            print(f"{Fore.BLUE}>>>> Ви: {message}{Style.RESET_ALL}")
            logging.info(f"Відправлено повідомлення для {receiver_name}: {message}")
        except Exception as e:
            logging.error(f"Помилка при відправці: {e}")

    client_socket.close()

if __name__ == "__main__":
    start_client()
