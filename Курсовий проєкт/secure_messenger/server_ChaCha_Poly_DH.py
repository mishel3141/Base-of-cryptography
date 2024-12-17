import socket
import threading
import logging
import signal
import sys
import json
import base64
from colorama import Fore, Style, init

# Ініціалізація colorama
init()

# Налаштування логування
logging.basicConfig(
    filename='logs/server.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

# Налаштування сервера
HOST = '127.0.0.1'
PORT = 12345

clients = {}
client_keys = {}
connected_clients = []
is_running = True

def broadcast(message, sender_socket):
    """Відправка повідомлення всім клієнтам, окрім відправника."""
    for client in clients.values():
        if client != sender_socket:
            try:
                client.send(message)
                logging.info(f"Переслано повідомлення: {message}")
            except Exception as e:
                logging.error(f"Помилка при відправці: {e}")
                remove_client(client)

def handle_client(client_socket, client_address):
    """Обробка клієнта."""
    logging.info(f"Підключено клієнта: {client_address}")
    clients[client_address] = client_socket

    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            message_data = json.loads(data.decode())
            logging.info(f"Отримано дані від {client_address}: {message_data}")

            # Обробка ключів DH
            if "dh_public" in message_data:
                client_keys[client_address] = message_data["dh_public"]
                if len(client_keys) == 2:
                    logging.info("Узгодження ключів для клієнтів...")
                    for addr, sock in clients.items():
                        peer_key = next((k for a, k in client_keys.items() if a != addr), None)
                        if peer_key:
                            response = {"status": "key_agreed", "peer_key": peer_key}
                            sock.send(json.dumps(response).encode())
                            logging.info(f"Надіслано key_agreed клієнту {addr}")
            # Обробка повідомлень
            elif "ciphertext" in message_data:
                broadcast(data, client_socket)
    except Exception as e:
        logging.error(f"Помилка з клієнтом {client_address}: {e}")
    finally:
        remove_client(client_socket)

def remove_client(client_socket):
    """Видалення клієнта."""
    for address, socket in list(clients.items()):
        if socket == client_socket:
            logging.info(f"Клієнт {address} відключено.")
            del clients[address]
            break
    client_socket.close()

def handle_sigint(signum, frame):
    """Завершення сервера при Ctrl+C."""
    global is_running
    print(f"{Fore.RED}\nЗупинка сервера...{Style.RESET_ALL}")
    logging.info("Сервер завершено за сигналом Ctrl+C.")
    is_running = False
    sys.exit(0)

def start_server():
    """Запуск сервера."""
    global is_running
    signal.signal(signal.SIGINT, handle_sigint)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"{Fore.GREEN}Сервер працює на {HOST}:{PORT}{Style.RESET_ALL}")
    logging.info(f"Сервер працює на {HOST}:{PORT}")

    while is_running:
        try:
            client_socket, client_address = server.accept()
            threading.Thread(target=handle_client, args=(client_socket, client_address)).start()
        except OSError:
            break

    server.close()
    logging.info("Сервер завершив роботу.")

if __name__ == "__main__":
    start_server()
