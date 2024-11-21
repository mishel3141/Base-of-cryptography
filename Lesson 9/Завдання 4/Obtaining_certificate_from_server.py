#
#  Отримання сертифікатів з сервера за допомоги OpenSSL для подальшої обробки в Python
#

import subprocess

def get_cert_chain_via_openssl(hostname):
    # Виконуємо команду openssl s_client
    command = ['openssl', 's_client', '-showcerts', '-connect', f'{hostname}:443']

    try:
        # Запуск команди через subprocess
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Отримуємо виведення
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")
        return None

if __name__ == "__main__":
    hostname = "robotdreams.cc"
    certs = get_cert_chain_via_openssl(hostname)
    if certs:
        print(certs)
