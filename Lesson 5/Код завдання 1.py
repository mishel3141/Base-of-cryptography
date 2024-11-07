from argon2 import PasswordHasher

# Ініціалізація хешера з налаштуваннями
# ph = PasswordHasher(time_cost=3, memory_cost=102400, parallelism=8)
ph = PasswordHasher()


# Паролі, які потрібно захешувати
passwords = ["qwertyuiop", "sofPed-westag-jejzo1", "f3Fg#Puu$EA1mfMx2", "TIMCfJDkKBRm9/zwcFbHhE6zaMcSxR7nke1mJKcVqXpvCzg69d7Mf2quanMoAfmPJXyqT4gyGpLoL1lTHoqmwVmaUwrpOPRecB8GAU17eUJJHiksv3qrqcVxhgpMkX/UlKaLdFSwFIr7cVoJmBqQ/buWzxJNCIo7qbtIi3fSi62NwMHh"]


# Хешування пароля
for _ in passwords:
  hashed_password = ph.hash(_)  

  # Виведення хешованого пароля
  print(f"Hashed password: {hashed_password}")

  # Перевірка пароля (порівняння введеного пароля з хешем)
  try:
      ph.verify(hashed_password, _)
      print("Password is valid.")
  except Exception as e:
      print("Password verification failed:", e)
