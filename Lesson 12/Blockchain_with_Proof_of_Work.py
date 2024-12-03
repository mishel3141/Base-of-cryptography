#
#                Генерація простого блокчейну
#  кожен блок містить дані з масиву values, відповідний хеш  
#  і значення nonce, яке забезпечує виконання Proof-of-Work
#

import hashlib
import time

# Функція для обчислення хешу блоку
def hash(data, prev_hash, nonce):
    # Створення строкового представлення для хешування
    block_string = str(data) + str(prev_hash) + str(nonce)
    return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

# Функція для генерації Proof-of-Work (минаємо блок)
def mine_block(block, difficulty=5):
    nonce = 0
    while True:
        # Генерація хешу для поточного блоку
        block_hash = hash(block['data'], block['prev_hash'], nonce)
        # Перевірка чи хеш має достатньо нулів на початку
        if block_hash[:difficulty] == '0' * difficulty:
            # Якщо так, зберігаємо nonce і повертаємо блок
            block['nonce'] = nonce
            block['hash'] = block_hash
            return block
        # Якщо не підходить, збільшуємо nonce і пробуємо знову
        nonce += 1

# Створення класу Блоку
class Block:
    def __init__(self, data, prev_hash=''):
        self.data = data
        self.prev_hash = prev_hash
        self.nonce = None
        self.hash = None

    # Створюємо метод для мінера (Proof-of-Work)
    def mine(self, difficulty):
        mined_block = mine_block(self.__dict__, difficulty)
        self.nonce = mined_block['nonce']
        self.hash = mined_block['hash']

# Функція для додавання нового блоку в блокчейн
def add_block(blockchain, data, difficulty=5):
    # Якщо блокчейн порожній, створюємо генезис-блок
    prev_hash = blockchain[-1].hash if blockchain else ''
    block = Block(data, prev_hash)
    block.mine(difficulty)
    blockchain.append(block)

# Створення Blockchain і додавання блоків
def create_blockchain(values, difficulty=5):
    blockchain = []
    for value in values:
        add_block(blockchain, value, difficulty)
    return blockchain

# Функція для виведення інформації про блоки
def print_blockchain(blockchain):
    for idx, block in enumerate(blockchain):
        print(f"Block {idx} - Data: {block.data} | Hash: {block.hash} | Nonce: {block.nonce}")

# Тестування
values = [91911, 90954, 95590, 97390, 96578, 97211, 95090]
difficulty = 5

# Створення blockchain
blockchain = create_blockchain(values, difficulty)

# Виведення інформації
print_blockchain(blockchain)
