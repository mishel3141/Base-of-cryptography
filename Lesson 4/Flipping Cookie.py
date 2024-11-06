# 
#   Оскільки справжній ключ не відомий, ми не можемо безпосередньо розшифрувати шифртекст. 
#   Але ми маємо можливість маніпулювати шифртекстом завдяки особливостям режиму шифрування AES-CBC. 
#   Cервер сам розшифровує шифртекст і перевіряє значення, 
#   тому ми можемо підробити частину шифртексту, щоб отримати "admin=True".
#   Підхід до атаки на CBC - це бітовий XOR для маніпуляцій. Скористуємося атакою на режим CBC, 
#   замінюючи IV або перший блок шифротексту. Ідея полягає в тому, щоб знайти правильне місце
#   та зробити XOR з потрібною різницею між "admin=False" і "admin=True".
#

import requests
import re
from Crypto.Util.Padding import pad

# Базовий URL сервера
base_url = 'http://aes.cryptohack.org/flipping_cookie'

def get_cookie():
    response = requests.get(f'{base_url}/get_cookie')
    data = response.json()
    iv_hex = data['cookie'][:32]
    ciphertext_hex = data['cookie'][32:]
    return bytes.fromhex(iv_hex), bytes.fromhex(ciphertext_hex)

def xor_bytes(a, b):
    # обчислюємо XOR-різницю для потрібних байтів.
    return bytes([x ^ y for x, y in zip(a, b)])

def modify_cookie_for_admin(iv, ciphertext):
    # Шукаємо місце для модифікації admin=False
    block_size = 16
    decrypted_plaintext_example = b"admin=False"  # Орієнтуємось на цей рядок
    target_plaintext = b"admin=True;"  # Те, що нам потрібно отримати

    # Розраховуємо різницю для XOR між "False" і "True;"
    diff = xor_bytes(decrypted_plaintext_example[6:11], target_plaintext[6:11])

    # Змінюємо відповідний байт IV для введення різниці
    modified_iv = bytearray(iv)
    for i in range(len(diff)):
        modified_iv[6 + i] ^= diff[i]  # зміна IV

    return bytes(modified_iv), ciphertext

def check_admin_access(modified_iv, ciphertext):
    # Відправляємо модифікований шифротекст на сервер
    iv_hex = modified_iv.hex()
    ciphertext_hex = ciphertext.hex()
    response = requests.get(f'{base_url}/check_admin/{ciphertext_hex}/{iv_hex}')
    return response.json()

# Основний процес
iv, ciphertext = get_cookie()
modified_iv, modified_ciphertext = modify_cookie_for_admin(iv, ciphertext)
result = check_admin_access(modified_iv, modified_ciphertext)

print(result)