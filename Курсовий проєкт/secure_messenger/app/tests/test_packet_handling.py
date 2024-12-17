from app.utilities import create_packet, parse_packet

def test_packet_creation():
    ciphertext = b"test_ciphertext"
    nonce = b"test_nonce"
    dh_public = b"test_dh_public"
    signature = b"test_signature"
    packet = create_packet(ciphertext, nonce, dh_public, signature)
    parsed = parse_packet(packet)
    assert parsed == (ciphertext, nonce, dh_public, signature), "Формування пакета працює некоректно!"
    print("Тест формування пакета пройдено.")

def test_packet_with_corruption():
    packet = b"test_ciphertext|test_nonce|test_dh_public"
    try:
        parse_packet(packet)
        assert False, "Розпакування пошкодженого пакета повинно провалитися."
    except ValueError:
        print("Тест із пошкодженим пакетом пройдено.")

if __name__ == "__main__":
    test_packet_creation()
    test_packet_with_corruption()
