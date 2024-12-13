# app/config.py

import logging
import os

# Налаштування логування
LOG_DIR = "logs/"
os.makedirs(LOG_DIR, exist_ok=True)  # Створюємо папку для логів, якщо її не існує

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "app.log"), mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("App")

# Параметри для шифрування
ENCRYPTION_ALGORITHM = 'ChaCha20'  # Використовуємо ChaCha20 замість AES
KEY_SIZE = 256  # Розмір ключа шифрування для ChaCha20

# Налаштування для Double Ratchet
DEFAULT_KEY_LIFETIME = 3600  # Час життя ключа в секундах (1 година)
