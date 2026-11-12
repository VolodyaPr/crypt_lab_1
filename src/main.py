import os
import json
import hashlib
import sys
import csv
import numpy as np
from PIL import Image

from cipher import (
    xor_encrypt_decrypt,
    aes_ecb_encrypt,
    aes_ecb_decrypt,
    aes_ctr_encrypt,
    aes_ctr_decrypt
)

from metrics import (
    calc_entropy,
    calc_correlation,
    save_histogram,
    calc_npcr_uaci
)

def run_lab_experiment():
    os.makedirs("imgs", exist_ok=True)
    os.makedirs("results", exist_ok=True)

    if len(sys.argv) > 1:
        img_name = sys.argv[1]
    else:
        img_name = "checkerboard.png"

    img_path = os.path.join("imgs", img_name)

    if not os.path.exists(img_path):
        print(f" Ошибка: Изображение '{img_path}' не найдено в папке imgs")
        return

    img = Image.open(img_path)
    img_size = img.size
    raw_pixels = img.tobytes()

    original_hash = hashlib.sha256(raw_pixels).hexdigest()
    print(f" Исходное изображение: {img_name} | Размер: {img_size}")
    print(f" SHA-256 исходника:   {original_hash}")
    print("-" * 75)

    xor_key = 123456789
    aes_key_1 = b'0123456789abcdef0123456789abcdef'

    results_table = []
    hist_data = {"Исходное": raw_pixels}

    # Метрики исходного изображения
    ent_orig = calc_entropy(raw_pixels)
    corr_h_orig, corr_v_orig = calc_correlation(np.array(img))

    # Потоковый XOR
    cipher_xor = xor_encrypt_decrypt(raw_pixels, xor_key)
    decrypted_xor = xor_encrypt_decrypt(cipher_xor, xor_key)
    hash_xor = hashlib.sha256(decrypted_xor).hexdigest()
    assert decrypted_xor == raw_pixels, "Ошибка обратимости XOR"

    hist_data["Потоковый XOR"] = cipher_xor
    ent_xor = calc_entropy(cipher_xor)
    cipher_xor_np = np.frombuffer(cipher_xor, dtype=np.uint8).reshape(img_size[1], img_size[0], -1) if len(img.getbands()) > 1 else np.frombuffer(cipher_xor, dtype=np.uint8).reshape(img_size[1], img_size[0])
    corr_h_xor, corr_v_xor = calc_correlation(cipher_xor_np)

    results_table.append({
        "Метод": "Потоковый XOR", "Энтропия": ent_xor, "Corr H": corr_h_xor, "Corr V": corr_v_xor, "Особенности": "Сохраняет силуэт исходных данных"
    })

    # AES-ECB
    cipher_ecb = aes_ecb_encrypt(raw_pixels, aes_key_1)
    decrypted_ecb = aes_ecb_decrypt(cipher_ecb, aes_key_1)
    hash_ecb = hashlib.sha256(decrypted_ecb).hexdigest()
    assert decrypted_ecb == raw_pixels, "Ошибка обратимости AES-ECB"

    hist_data["AES-ECB"] = cipher_ecb
    ent_ecb = calc_entropy(cipher_ecb)
    cipher_ecb_trimmed = cipher_ecb[:len(raw_pixels)]
    cipher_ecbraw = np.frombuffer(cipher_ecb_trimmed, dtype=np.uint8).reshape(img_size[1], img_size[0], -1) if len(img.getbands()) > 1 else np.frombuffer(cipher_ecb_trimmed, dtype=np.uint8).reshape(img_size[1], img_size[0])
    corr_h_ecb, corr_v_ecb = calc_correlation(cipher_ecbraw)

    results_table.append({
        "Метод": "AES-ECB", "Энтропия": ent_ecb, "Corr H": corr_h_ecb, "Corr V": corr_v_ecb, "Особенности": "Сохраняет блочные паттерны и контуры"
    })

    # AES-CTR
    cipher_ctr, nonce = aes_ctr_encrypt(raw_pixels, aes_key_1)
    decrypted_ctr = aes_ctr_decrypt(cipher_ctr, aes_key_1, nonce)
    hash_ctr = hashlib.sha256(decrypted_ctr).hexdigest()
    assert decrypted_ctr == raw_pixels, "Ошибка обратимости AES-CTR"

    hist_data["AES-CTR"] = cipher_ctr
    ent_ctr = calc_entropy(cipher_ctr)
    cipher_ctrraw = np.frombuffer(cipher_ctr, dtype=np.uint8).reshape(img_size[1], img_size[0], -1) if len(img.getbands()) > 1 else np.frombuffer(cipher_ctr, dtype=np.uint8).reshape(img_size[1], img_size[0])
    corr_h_ctr, corr_v_ctr = calc_correlation(cipher_ctrraw)

    results_table.append({
        "Метод": "AES-CTR", "Энтропия": ent_ctr, "Corr H": corr_h_ctr, "Corr V": corr_v_ctr, "Особенности": "Полное разрушение структуры"
    })

    # Проверка обратимости
    print(" Проверка обратимости:")
    print(f"    - Потоковый XOR : {'СОВПАДАЕТ' if hash_xor == original_hash else 'ОШИБКА'}")
    print(f"    - AES-ECB       : {'СОВПАДАЕТ' if hash_ecb == original_hash else 'ОШИБКА'}")
    print(f"    - AES-CTR       : {'СОВПАДАЕТ' if hash_ctr == original_hash else 'ОШИБКА'}")
    print("-" * 75)

    # Итоговая таблица
    full_table = [{
        "Метод": "Исходное", "Энтропия": ent_orig, "Corr H": corr_h_orig, "Corr V": corr_v_orig, "Особенности": "Структура изображения"
    }] + results_table

    print("\n" + "=" * 85)
    print(f"{'Метод':<18} | {'Энтропия':<10} | {'Corr H':<10} | {'Corr V':<10} | {'Особенности':<25}")
    print("=" * 85)
    for r in full_table:
        print(f"{r['Метод']:<18} | {r['Энтропия']:<10.4f} | {r['Corr H']:<10.4f} | {r['Corr V']:<10.4f} | {r['Особенности']:<25}")
    print("=" * 85)

    with open("results/metrics.csv", mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Метод", "Энтропия", "Corr H", "Corr V", "Особенности"])
        writer.writeheader()
        writer.writerows(full_table)

    # Изменение ключа
    print("\n Эксперимент с чувствительностью к ключу")
    aes_key_m = bytearray(aes_key_1)
    aes_key_m[0] ^= 0x01
    aes_key_mod = bytes(aes_key_m)

    cipher_ctr_2, _ = aes_ctr_encrypt(raw_pixels, aes_key_mod, nonce)
    npcr, uaci = calc_npcr_uaci(cipher_ctr, cipher_ctr_2)

    print(f"    -> NPCR = {npcr:.2f}%")
    print(f"    -> UACI = {uaci:.2f}%")

    save_histogram(hist_data, "results/histograms.png")

    meta_data = [
        {
            "algorithm": "xor",
            "source": img_name
        },
        {
            "algorithm": "aes-ecb",
            "source": img_name
        },
        {
            "algorithm": "aes-ctr",
            "nonce": nonce.hex(),
            "source": img_name
        },
        {
            "algorithm": "aes-ctr",
            "nonce": nonce.hex(),
            "source": img_name
        }
    ]

    with open("results/meta.json", "w", encoding="utf-8") as f:
        json.dump(meta_data, f, indent=4)

if __name__ == "__main__":
    run_lab_experiment()