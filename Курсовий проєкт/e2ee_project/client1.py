import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Завантаження ключів клієнта
with open("keys/Alice/alice_private_key.pem", "rb") as f:
    private_key = RSA.import_key(f.read())
with open("keys/Alice/alice_public_key.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

server_url = "http://127.0.0.1:5000"

def encrypt_and_send_message(message):
    with open("keys/Bob/bob_public_key.pem", "rb") as f:
        server_public_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(server_public_key)
    encrypted_message = cipher.encrypt(message.encode())

    response = requests.post(f"{server_url}/encrypt", json={
        "message": message,
        "client_public_key": public_key.export_key().decode()
    })

    print("Response:", response.json())

def decrypt_message(encrypted_message):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(bytes.fromhex(encrypted_message))
    print("Decrypted message:", decrypted_message.decode())

def sign_message(message):
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)

    response = requests.post(f"{server_url}/sign", json={
        "message": message
    })

    print("Response:", response.json())
    return signature.hex()

def verify_signature(message, signature):
    response = requests.post(f"{server_url}/verify", json={
        "message": message,
        "signature": signature
    })

    print("Response:", response.json())

if __name__ == "__main__":
    message = "Hello, secure world!"
    encrypt_and_send_message(message)

    # Example signature verification
    signature = sign_message(message)
    verify_signature(message, signature)
