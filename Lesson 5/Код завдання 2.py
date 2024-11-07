import hmac
import hashlib
from binascii import unhexlify

# Дано:
key_hex = "63e353ae93ecbfe00271de53b6f02a46"  # Головний ключ
ciphertext_hex = "76c3ada7f1f7563ff30d7290e58fb4476eb12997d02a6488201c075da52ff3890260e2c89f631e7f919af96e4e47980a"  # Шифротекст
iv_hex = "75b777fc8f70045c6006b39da1b3d622"  # Вектор ініціалізації

# Перетворення з шестнадцяткового формату в байти
key = unhexlify(key_hex)
ciphertext = unhexlify(ciphertext_hex)
iv = unhexlify(iv_hex)

# Об'єднуємо IV та шифротекст для включення в MAC
data_for_mac = iv + ciphertext

# Генерація HMAC-SHA256
mac = hmac.new(key, data_for_mac, hashlib.sha256).hexdigest()

# Виведення результату
print(f"Message Authentication Code (MAC): {mac}")

