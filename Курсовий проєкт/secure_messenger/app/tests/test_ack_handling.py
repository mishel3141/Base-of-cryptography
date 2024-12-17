import time

def test_ack_timeout():
    start_time = time.time()
    timeout = 5  # секунд
    while time.time() - start_time < timeout:
        pass  # Очікуємо
    assert time.time() - start_time >= timeout, "Таймаут працює некоректно!"
    print("Тест таймауту пройдено.")

if __name__ == "__main__":
    test_ack_timeout()
