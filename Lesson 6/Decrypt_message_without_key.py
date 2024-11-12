from Crypto.Util.number import long_to_bytes

# Параметри з output.txt
n = 89130176363968657187562046515332781879906710777886742664996031757940362853930049819009596594982246571669482031940134479813793328701373238273415076270891142859666516439231904521557755729322490606876589914024096621194962329718893576886641536066926542462448229133783052051407061075447588804617825930836181625077
e = 1
ct = ct = 9525146106593233668246438912833048755472216768584708733

# Розшифрування
pt = ct  # Оскільки e = 1, шифротекст дорівнює plaintext
decrypted_message = long_to_bytes(pt)

print("Розшифроване повідомлення:", decrypted_message.decode('utf-8'))