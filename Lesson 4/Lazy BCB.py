# Реалізація атаки Lazy CBC, де IV збігається з ключем, з метою отримання секретного ключа і флагу.

# Крок 1.  URL-адреси для API запитів до сервера

encryptURL = "https://aes.cryptohack.org/lazy_cbc/encrypt//"          # Шифрує повідомлення (encryptURL)
decryptURL = "https://aes.cryptohack.org/lazy_cbc/receive//"          # Дешифрує (з можливим поверненням помилки) (decryptURL)
flagURL = "https://aes.cryptohack.org/lazy_cbc/get_flag//"            # Повертає флаг, якщо ключ правильний (flagURL)

# Крок 2. Генерація "порожнього" шифротексту

plaintext = b'?' * 16  # Відправляємо заповнені '?' дані довжиною 16 байт
chipertext = bytes.fromhex(requests.get(encryptURL + plaintext.hex()).json()['ciphertext'])    #  Відправляється на сервер для шифрування
# Сервер повертає ciphertext, який отримується через .json()['ciphertext']

# Крок 3. Генерація підробного шифротексту

x = [0] * 16
psevdo_ciphertext = bytes(x) + chipertext    # Імітація підробного IV: перший блок заповнюється нулями
mix_IV = bytes.fromhex(requests.get(decryptURL + psevdo_ciphertext.hex()).json()["error"].split("Invalid plaintext: ")[1])  # Відправка на сервер для дешифрування
# Отримується помилка з частиною "Invalid plaintext", яка містить IV ⊕ Plaintext.

# Крок 4. Відновлення ключа

key = [x ^ y for x, y in zip(plaintext, mix_IV[16:])]  # Ключ обчислюється через plaintext ⊕ mix_IV.

# Крок 5. Отримання флагу

flag = bytes.fromhex(requests.get(flagURL + bytes(key).hex()).json()["plaintext"])  # Після відновлення ключа робиться запит на сервер для отримання флагу.

# Крок 6. Вивід результату

print("flag:", flag)