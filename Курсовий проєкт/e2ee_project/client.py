import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import base64

# Генеруємо ключі клієнта
client_private_key = X25519PrivateKey.generate()
client_public_key = client_private_key.public_key()

# Відправляємо публічний ключ на сервер
server_url = 'http://127.0.0.1:5000/exchange_key'
client_public_key_b64 = base64.b64encode(client_public_key.public_bytes()).decode()
response = requests.post(server_url, json={'client_public_key': client_public_key_b64})

# Обробляємо відповідь сервера
data = response.json()
server_public_key_b64 = data.get('server_public_key')
server_public_key = base64.b64decode(server_public_key_b64)

print(f"Server public key received: {server_public_key_b64}")
