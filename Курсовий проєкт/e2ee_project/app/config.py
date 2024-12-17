# app/config.py

import logging

# Налаштування логування
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("double_ratchet")  # Логгер для Double Ratchet

# Параметри для шифрування
ENCRYPTION_ALGORITHM = 'ChaCha20'  # Використовуємо ChaCha20 замість AES
KEY_SIZE = 256  # Розмір ключа шифрування для ChaCha20

# Налаштування для Double Ratchet
DEFAULT_KEY_LIFETIME = 3600  # Час життя ключа в секундах (1 година)
