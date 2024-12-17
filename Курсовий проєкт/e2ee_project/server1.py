from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

app = Flask(__name__)

# Завантаження ключів сервера
with open("keys/Bob/bob_private_key.pem", "rb") as f:
    private_key = RSA.import_key(f.read())
with open("keys/Bob/bob_public_key.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    data = request.json.get("message", "")
    client_public_key_pem = request.json.get("client_public_key", "")

    if not data or not client_public_key_pem:
        return jsonify({"error": "Invalid input"}), 400

    client_public_key = RSA.import_key(client_public_key_pem.encode())
    cipher = PKCS1_OAEP.new(client_public_key)
    encrypted_message = cipher.encrypt(data.encode())

    return jsonify({"encrypted_message": encrypted_message.hex()}), 200

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    encrypted_message = request.json.get("encrypted_message", "")

    if not encrypted_message:
        return jsonify({"error": "Invalid input"}), 400

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(bytes.fromhex(encrypted_message))

    return jsonify({"decrypted_message": decrypted_message.decode()}), 200

@app.route('/sign', methods=['POST'])
def sign_message():
    data = request.json.get("message", "")

    if not data:
        return jsonify({"error": "Invalid input"}), 400

    h = SHA256.new(data.encode())
    signature = pkcs1_15.new(private_key).sign(h)

    return jsonify({"signature": signature.hex()}), 200

@app.route('/verify', methods=['POST'])
def verify_signature():
    data = request.json.get("message", "")
    signature = request.json.get("signature", "")

    if not data or not signature:
        return jsonify({"error": "Invalid input"}), 400

    h = SHA256.new(data.encode())
    try:
        pkcs1_15.new(public_key).verify(h, bytes.fromhex(signature))
        return jsonify({"verified": True}), 200
    except (ValueError, TypeError):
        return jsonify({"verified": False}), 400

if __name__ == '__main__':
    app.run(port=5000, debug=True)
