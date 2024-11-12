# Код завдання 4 щодо дешифрування повідомлення без використання секретного ключа для експоненти е=3

from Crypto.Util.number import long_to_bytes
from sympy import cbrt

# Завантажити параметри з файлу
with open("output.txt", "r") as file:
    data = file.read().strip().split("\n")
    n = int(data[0].split(" = ")[1])
    e = int(data[1].split(" = ")[1])
    ct = int(data[2].split(" = ")[1])

# Перевірка вразливості
if ct < n:
    # Знаходимо кубічний корінь
    pt = int(cbrt(ct))
    decrypted_message = long_to_bytes(pt)
    print("Розшифроване повідомлення:", decrypted_message.decode('utf-8'))
else:
    print("Шифротекст перевищує модуль, ця атака не працює.")