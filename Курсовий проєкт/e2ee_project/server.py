from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import base64

app = Flask(__name__)

# Генеруємо власні ключі сервера
server_private_key = X25519PrivateKey.generate()
server_public_key = server_private_key.public_key()

@app.route('/exchange_key', methods=['POST'])
def exchange_key():
    client_public_key_b64 = request.json.get('client_public_key')
    client_public_key = X25519PublicKey.from_public_bytes(base64.b64decode(client_public_key_b64))
    
    # Обчислюємо спільний секрет
    shared_secret = server_private_key.exchange(client_public_key)
    
    # Відправляємо серверний публічний ключ клієнту
    server_public_key_b64 = base64.b64encode(server_public_key.public_bytes()).decode()
    return jsonify({'server_public_key': server_public_key_b64, 'message': 'Key exchange successful'})

if __name__ == '__main__':
    app.run(debug=True)
