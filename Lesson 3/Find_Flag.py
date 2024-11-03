#     Програма для розкриття FLAG базується на вразливості шифрування AES
#               в режимі Electronic Codebook за допомоги техніки,
#                   відомої як "Byte-at-a-time ECB Decryption"

import requests

URL = "http://aes.cryptohack.org/ecb_oracle/encrypt/"

def get_encrypted_data(plaintext):
    """Запит на сервер для отримання шифрованого тексту"""
    response = requests.get(f"{URL}/{plaintext.hex()}/")
    return bytes.fromhex(response.json()["ciphertext"])

def find_flag():
    """ Пошук Flag """
    block_size = 16  # Блок для AES
    flag = b""

    for i in range(1, 256):  # Максимальна довжина FLAG
        pad_text = b"?" * (block_size - (len(flag) + 1) % block_size)
        encrypted_block = get_encrypted_data(pad_text)

        # Порівняємо блоки для пошуку фрагмента `FLAG`
        known_block = encrypted_block[: len(pad_text) + len(flag) + 1]

        # Перебір для кожного байта
        for byte in range(256):
            trial_text = pad_text + flag + bytes([byte])
            encrypted_trial = get_encrypted_data(trial_text)

            if encrypted_trial[: len(known_block)] == known_block:
                flag += bytes([byte])
                print("Знайдений байт:", bytes([byte]))
                break

        if b"crypto{" in flag and flag.endswith(b"}"):    # рішення знайдено
            break

    return flag

# Запуск для знаходження `FLAG`
print("FLAG:", find_flag().decode())
