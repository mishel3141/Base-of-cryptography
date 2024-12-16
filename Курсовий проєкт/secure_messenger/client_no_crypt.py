import socket
import threading
import logging
from colorama import Fore, Style, init

# Ініціалізація colorama
init()

# Налаштування логування
logging.basicConfig(filename='logs/client.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Налаштування сервера
HOST = '127.0.0.1'
PORT = 12345

def receive_messages(client_socket):
    """Слухати та відображати вхідні повідомлення від сервера."""
    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                break
            log_message = f"Отримано: {message.decode()}"
            logging.info(log_message)
            print(f"{Fore.RED}<<<< {log_message} {Style.RESET_ALL}")  # Червоний колір для отриманих повідомлень
        except:
            error_message = "Відключено від сервера."
            logging.error(error_message)
            print(f"{Fore.LIGHTBLACK_EX}{error_message}{Style.RESET_ALL}")  # Сірий для системних повідомлень
            break

def start_client():
    """Підключення до сервера та обробка відправки/отримання повідомлень."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
        connection_message = "Підключено до сервера. Введіть повідомлення нижче."
        logging.info(connection_message)
        print(f"{Fore.LIGHTBLACK_EX}{connection_message}{Style.RESET_ALL}")
        threading.Thread(target=receive_messages, args=(client_socket,)).start()
    except Exception as e:
        error_message = f"Не вдалося підключитися до сервера: {e}"
        logging.error(error_message)
        print(f"{Fore.LIGHTBLACK_EX}{error_message}{Style.RESET_ALL}")
        return

    while True:
        try:
            message = input()
            if message.lower() == 'exit':
                exit_message = "Вихід з чату."
                logging.info(exit_message)
                print(f"{Fore.LIGHTBLACK_EX}{exit_message}{Style.RESET_ALL}")
                break
            client_socket.send(message.encode())
            log_message = f"Відправлено: {message}"
            logging.info(log_message)
            print(f"{Fore.BLUE}>>>> {log_message} {Style.RESET_ALL}")  # Синій колір для відправлених повідомлень
        except Exception as e:
            error_message = f"Помилка при відправці повідомлення: {e}"
            logging.error(error_message)
            print(f"{Fore.LIGHTBLACK_EX}{error_message}{Style.RESET_ALL}")
            break
    client_socket.close()

if __name__ == "__main__":
    start_client()