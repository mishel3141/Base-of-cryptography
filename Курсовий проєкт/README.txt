Secure Messenger with End-to-End Encryption


Опис проєкту

Цей проєкт реалізує наскрізне шифрування (E2EE) для обміну повідомленнями між двома клієнтами 
через пасивний сервер. Система використовує сучасні криптографічні алгоритми, такі як ChaCha20-
Poly1305 для шифрування повідомлень, Діффі-Хеллман (DH) для узгодження ключів, а також Double 
Ratchet для забезпечення прямої секретності та оновлення ключів після кожного повідомлення.


Функціональність

-  Наскрізне шифрування (End-to-End Encryption): повідомлення шифруються на стороні відправника 
   та розшифровуються тільки на стороні отримувача.
-  DH-обмін ключами: перший обмін ключами для встановлення спільного секрету.
-  Double Ratchet: оновлення ключів після кожного повідомлення для прямої секретності.
-  ChaCha20-Poly1305: сучасний алгоритм AEAD для шифрування та забезпечення цілісності повідомлень.
-  Сервер-транзит: сервер лише передає зашифровані повідомлення та не має доступу до їх вмісту.


Використані технології

-  Мова програмування: Python 3.x
-  Криптографія: cryptography (ChaCha20-Poly1305, X25519 для DH-обміну)
-  Робота з мережею: socket для клієнт-серверного зв'язку
-  Логування: logging для фіксації подій
-  Кольоровий вивід: colorama для зручності виводу повідомлень


Встановлення

1. Встановіть Python: переконайтеся, що встановлено Python 3.x.
2. Встановіть необхідні бібліотеки. Виконайте команду:  pip install cryptography colorama


Запуск системи

1. Запустіть сервер, який буде передавати зашифровані повідомлення:  python server.py
   Очікуваний вивід:   Сервер працює на 127.0.0.1:12345

2. Запустіть клієнтів: кожен клієнт запускається окремо з передачею свого імені та 
   імені співрозмовника:
           python client.py Alice Bob
           python client.py Bob Alice
    Очікуваний вивід:   Підключено до сервера як Alice.
                        Спільний ключ успішно узгоджено.
                        >>> Hello, Bob!
                        >>>> Ви: Hello, Bob!


Формат повідомлень

DH-публічний ключ передається при узгодженні.
Повідомлення включають:
-  Ciphertext: зашифроване повідомлення.
-  Nonce: унікальний вектор ініціалізації для ChaCha20-Poly1305.
-  DH-публічний ключ: для оновлення ключів Double Ratchet.


Приклади використання

Запуск сервера:  python server.py
Запуск клієнтів: python client.py Alice Bob
                 python client.py Bob Alice

Вихід із чату: для завершення роботи введіть команду: exit.


Файлова структура

secure_messenger/
│
├── server.py                   # Код сервера
├── client.py                   # Код клієнта
├── logs/
│   ├── server.log              # Логи сервера
│   └── client.log              # Логи клієнта
└── README.md                   # Цей файл


Безпека

-  DH-обмін: ключі узгоджуються безпечно через X25519.
-  Double Ratchet: забезпечує оновлення ключів для кожного повідомлення.
-  ChaCha20-Poly1305: шифрує повідомлення та забезпечує їхню цілісність.
-  Пряма секретність: компрометація одного ключа не дозволяє розшифрувати попередні чи 
   наступні повідомлення.

Захист від відомих атак

Рішення захищає від наступних відомих атак:
-	Компрометація ключа (Key Compromise):  використання Double Ratchet забезпечує, що навіть якщо
    один із ключів буде скомпрометовано, інші повідомлення залишаться захищеними.
-	Атаки типу "чоловік посередині" (Man-in-the-Middle):  DH-обмін ключами із верифікацією публічних 
    ключів через цифровий підпис запобігає можливості перехоплення або заміни ключів.
-	Атаки на довільне перепризначення (Key Substitution Attacks):  кожне повідомлення пов’язане з 
    унікальним ключем, що генерується за допомогою Double Ratchet.
-	Захоплення ключів сесії (Session Key Extraction):  спільний секрет обчислюється лише на момент 
    встановлення сесії та ніколи не передається через мережу в незашифрованому вигляді.
-	Атаки типу "пересилання повідомлення іншому клієнту" (Forwarding Attacks):  пакети пов’язуються 
    з конкретним відправником і отримувачем, що перевіряється під час обробки.
-	Витік інформації про порядок повідомлень (Traffic Analysis):  хоча метадані не шифруються, сервер 
    не має доступу до вмісту повідомлень завдяки наскрізному шифруванню.

Відома проблема

Якщо один із клієнтів відключиться, обмін ключами потрібно буде провести повторно при 
перепідключенні.
