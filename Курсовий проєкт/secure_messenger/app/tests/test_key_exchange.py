from app.utilities import generate_key_pair, derive_shared_secret

def test_key_exchange():
    private_key, public_key = generate_key_pair()
    partner_private_key, partner_public_key = generate_key_pair()
    shared_secret1 = derive_shared_secret(private_key, partner_public_key)
    shared_secret2 = derive_shared_secret(partner_private_key, public_key)
    assert shared_secret1 == shared_secret2, "Обмін ключами працює некоректно!"
    print("Тест обміну ключами пройдено.")

if __name__ == "__main__":
    test_key_exchange()
