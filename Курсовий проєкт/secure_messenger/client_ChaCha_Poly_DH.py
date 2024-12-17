import socket
import threading
import logging
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from colorama import Fore, Style, init

# Ініціалізація colorama
init()

# Налаштування логування
logging.basicConfig(
    filename='logs/client.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Налаштування сервера
HOST = '127.0.0.1'
PORT = 12345

# Генерація ключів DH
dh_private_key = x25519.X25519PrivateKey.generate()
dh_public_key = dh_private_key.public_key()
shared_key = None

def encrypt_message(message: str, key: bytes):
    nonce = ChaCha20Poly1305.generate_key()[:12]
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, message.encode(), None)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }

def decrypt_message(data: dict, key: bytes) -> str:
    chacha = ChaCha20Poly1305(key)
    ciphertext = base64.b64decode(data['ciphertext'])
    nonce = base64.b64decode(data['nonce'])
    return chacha.decrypt(nonce, ciphertext, None).decode()

def receive_messages(client_socket):
    global shared_key
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                break
            message_data = json.loads(data.decode())
            logging.info(f"Отримано: {message_data}")

            if message_data.get("status") == "key_agreed":
                peer_key_bytes = base64.b64decode(message_data["peer_key"])
                peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_key_bytes)
                shared_key = dh_private_key.exchange(peer_public_key)[:32]
                print(f"{Fore.GREEN}Сесійний ключ успішно узгоджено!{Style.RESET_ALL}")
            elif shared_key and "ciphertext" in message_data:
                plaintext = decrypt_message(message_data, shared_key)
                print(f"{Fore.RED}<<<< {message_data['sender']}: {plaintext}{Style.RESET_ALL}")
            else:
                logging.warning("Отримано невідомі дані.")
        except Exception as e:
            logging.error(f"Помилка при отриманні: {e}")

def start_client():
    global shared_key
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print(f"{Fore.GREEN}Підключено до сервера.{Style.RESET_ALL}")
    threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

    # Надсилання публічного ключа
    client_socket.send(json.dumps({
        "dh_public": base64.b64encode(dh_public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )).decode()
    }).encode())

    while True:
        message = input(">>> ")
        if message.lower() == 'exit':
            print(f"{Fore.LIGHTBLACK_EX}Вихід з чату.{Style.RESET_ALL}")
            break
        if shared_key:
            encrypted_message = encrypt_message(message, shared_key)
            encrypted_message["sender"] = f"Client-{id(client_socket)}"
            client_socket.send(json.dumps(encrypted_message).encode())
            print(f"{Fore.BLUE}>>>> Ви: {message}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Сесійний ключ ще не узгоджено. Очікуйте...{Style.RESET_ALL}")

if __name__ == "__main__":
    start_client()
