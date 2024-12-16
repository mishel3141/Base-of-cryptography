import socket
import threading
import logging

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

# Глобальний список клієнтів
clients = []

def broadcast(message, sender_socket):
    """Відправка повідомлення всім клієнтам, окрім відправника."""
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message)
            except:
                clients.remove(client)
                logging.warning(f"Клієнт відключений: {client.getpeername()}")

def handle_client(client_socket, client_address):
    """Обробка комунікації з підключеним клієнтом."""
    logging.info(f"Клієнт підключений: {client_address}")
    clients.append(client_socket)
    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                break
            logging.info(f"Отримано повідомлення від {client_address}: {message.decode()}\n")
            broadcast(message, client_socket)
        except Exception as e:
            logging.error(f"Помилка з клієнтом {client_address}: {e}")
            break
    logging.info(f"Клієнт відключений: {client_address}")
    clients.remove(client_socket)
    client_socket.close()

def start_server():
    """Запуск сервера та обробка підключень."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, PORT))
        server.listen(5)
        logging.info(f"Сервер запущено та працює на {HOST}:{PORT}")
        print(f"Сервер запущено та працює на {HOST}:{PORT}")
    except Exception as e:
        logging.error(f"Не вдалося запустити сервер: {e}")
        return

    while True:
        try:
            client_socket, client_address = server.accept()
            logging.info(f"Підключення клієнта: {client_address}")
            threading.Thread(target=handle_client, args=(client_socket, client_address)).start()
        except Exception as e:
            logging.error(f"Помилка при прийомі підключення: {e}")

if __name__ == "__main__":
    start_server()
