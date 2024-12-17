import socket
import threading
import logging
import json
import time
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
client_names = {}
dh_public_keys = {}  # Збереження DH-публічних ключів


def broadcast_dh_keys():
    """Розсилає DH-публічні ключі між усіма підключеними клієнтами."""
    if len(clients) == 2:  # Потрібно обидва клієнти
        for client_address, client_socket in clients.items():
            for peer_name, peer_key in dh_public_keys.items():
                client_name = client_names[client_address]
                if client_name != peer_name:
                    client_socket.send(json.dumps({
                        "dh_public": peer_key,
                        "peer_name": peer_name
                    }).encode())
                    logging.info(f"Надіслано DH-ключ {peer_name} клієнту {client_name}.")
                    print(f"{Fore.CYAN}Надіслано DH-ключ {peer_name} клієнту {client_name}.{Style.RESET_ALL}")


def handle_client(client_socket, client_address):
    """Обробка клієнта."""
    try:
        # Отримання імені та DH-публічного ключа клієнта
        data = client_socket.recv(4096)
        initial_data = json.loads(data.decode())
        name = initial_data.get("name", f"Client-{client_address}")
        dh_public = initial_data.get("dh_public", None)

        if dh_public:
            dh_public_keys[name] = dh_public  # Збереження публічного ключа
        client_names[client_address] = name
        clients[client_address] = client_socket
        logging.info(f"{name} підключився з DH-публічним ключем.")
        print(f"{Fore.GREEN}Клієнт {name} підключився.{Style.RESET_ALL}")

        # Якщо два клієнти підключені, розсилаємо ключі
        if len(clients) == 2:
            time.sleep(1)  # Пауза для стабільності
            broadcast_dh_keys()

        # Основний цикл обробки повідомлень
        while True:
            data = client_socket.recv(4096)
            if not data:
                break

            message_data = json.loads(data.decode())
            receiver_name = message_data.get("receiver", None)

            if receiver_name:
                success = send_to_client(receiver_name, json.dumps({
                    "sender": client_names[client_address],
                    "message": message_data["message"]
                }).encode())
                if success:
                    logging.info(f"Повідомлення від {name} надіслано до {receiver_name}.")
                else:
                    logging.warning(f"Не вдалося надіслати повідомлення до {receiver_name}.")
            else:
                logging.warning("Отримано повідомлення без отримувача.")
    except ConnectionResetError:
        logging.warning(f"Клієнт {client_names.get(client_address)} розірвав з'єднання.")
    except Exception as e:
        logging.error(f"Помилка з клієнтом {client_names.get(client_address)}: {e}")
    finally:
        remove_client(client_socket, client_address)


def send_to_client(receiver_name, message):
    """Надсилання повідомлення конкретному клієнту."""
    for address, name in client_names.items():
        if name == receiver_name:
            try:
                clients[address].send(message)
                return True
            except Exception as e:
                logging.error(f"Помилка відправлення до {receiver_name}: {e}")
                return False
    return False


def remove_client(client_socket, client_address):
    """Видалення клієнта зі списків і закриття з'єднання."""
    name = client_names.get(client_address, client_address)
    if client_address in clients:
        del clients[client_address]
    if name in dh_public_keys:
        del dh_public_keys[name]
    if client_address in client_names:
        del client_names[client_address]
    client_socket.close()
    logging.info(f"{name} відключено.")
    print(f"{Fore.RED}Клієнт {name} відключено.{Style.RESET_ALL}")


def start_server():
    """Запуск сервера та очікування підключень."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"{Fore.GREEN}Сервер працює на {HOST}:{PORT}{Style.RESET_ALL}")
    logging.info(f"Сервер працює на {HOST}:{PORT}")

    try:
        while True:
            client_socket, client_address = server.accept()
            print(f"{Fore.BLUE}Підключення клієнта: {client_address}{Style.RESET_ALL}")
            logging.info(f"Підключення клієнта: {client_address}")
            threading.Thread(target=handle_client, args=(client_socket, client_address)).start()
    except KeyboardInterrupt:
        print(f"{Fore.RED}\nСервер зупинено вручну.{Style.RESET_ALL}")
        logging.info("Сервер зупинено вручну.")
    finally:
        server.close()


if __name__ == "__main__":
    start_server()
