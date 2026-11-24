import os
import sys
import json
import hashlib
import csv
import numpy as np
from PIL import Image

from cipher import (
    xor_encrypt_decrypt,
    aes_ecb_encrypt,
    aes_ecb_decrypt,
    aes_ctr_encrypt,
    aes_ctr_decrypt,
)
from metrics import (
    calc_entropy,
    calc_correlation,
    save_histogram,
    calc_npcr_uaci,
)


def bytes_to_image(raw: bytes, size: tuple[int, int], mode: str) -> Image.Image:
    return Image.frombytes(mode, size, raw)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def run_lab_experiment():
    os.makedirs("imgs", exist_ok=True)
    os.makedirs("results", exist_ok=True)

    img_name = sys.argv[1] if len(sys.argv) > 1 else "checkerboard.png"
    img_path = os.path.join("imgs", img_name)
    if not os.path.exists(img_path):
        print(f"Не найдено: {img_path}")
        return

    o_name = os.path.splitext(img_name)[0]

    with Image.open(img_path) as im:
        if im.mode not in ("RGB", "RGBA", "L"):
            im = im.convert("RGB")
        img_size = im.size
        img_mode = im.mode
        raw_pixels = im.tobytes()
        orig_np = np.array(im)

    original_hash = sha256(raw_pixels)
    print(f"Изображение: {img_name} | {img_size} | mode={img_mode} | байт={len(raw_pixels)}")
    print(f"SHA-256 исходника: {original_hash}")
    print("-" * 78)

    # Ключи
    xor_key = 123456789
    aes_key = b"0123456789abcdef0123456789abcdef"  # 32 байта - AES-256
    print(f"AES: {len(aes_key) * 8}-бит (AES-256)")

    # Файлы
    enc_xor_png = os.path.join("imgs", f"enc_xor_{o_name}.png")
    dec_xor_png = os.path.join("imgs", f"dec_xor_{o_name}.png")
    enc_ecb_bin = os.path.join("results", f"enc_ecb_{o_name}.bin")
    enc_ecb_png = os.path.join("imgs", f"enc_ecb_{o_name}.png")
    dec_ecb_png = os.path.join("imgs", f"dec_ecb_{o_name}.png")
    enc_ctr_png = os.path.join("imgs", f"enc_ctr_{o_name}.png")
    dec_ctr_png = os.path.join("imgs", f"dec_ctr_{o_name}.png")

    # 1 Потоковый XOR
    cipher_xor = xor_encrypt_decrypt(raw_pixels, xor_key)
    bytes_to_image(cipher_xor, img_size, img_mode).save(enc_xor_png)

    # читаем зашифрованный PNG с диска и расшифровываем из файла
    with Image.open(enc_xor_png) as f:
        enc_xor_from_disk = f.tobytes()
    restored_xor = xor_encrypt_decrypt(enc_xor_from_disk, xor_key)
    bytes_to_image(restored_xor, img_size, img_mode).save(dec_xor_png)
    with Image.open(dec_xor_png) as f:
        restored_xor_from_disk = f.tobytes()

    hash_xor_ok = sha256(restored_xor_from_disk) == original_hash

    # 2 AES-ECB
    cipher_ecb = aes_ecb_encrypt(raw_pixels, aes_key)
    with open(enc_ecb_bin, "wb") as f:
        f.write(cipher_ecb)

    bytes_to_image(cipher_ecb[:len(raw_pixels)], img_size, img_mode).save(enc_ecb_png)

    # читаем полный шифротекст из bin расшифровываем и сохраняем png
    with open(enc_ecb_bin, "rb") as f:
        cipher_ecb_from_disk = f.read()
    restored_ecb = aes_ecb_decrypt(cipher_ecb_from_disk, aes_key)
    bytes_to_image(restored_ecb, img_size, img_mode).save(dec_ecb_png)
    with Image.open(dec_ecb_png) as f:
        restored_ecb_from_disk = f.tobytes()

    hash_ecb_ok = sha256(restored_ecb_from_disk) == original_hash

    # 3 AES-CTR
    cipher_ctr, nonce = aes_ctr_encrypt(raw_pixels, aes_key)
    bytes_to_image(cipher_ctr, img_size, img_mode).save(enc_ctr_png)

    with Image.open(enc_ctr_png) as f:
        enc_ctr_from_disk = f.tobytes()
    restored_ctr = aes_ctr_decrypt(enc_ctr_from_disk, aes_key, nonce)
    bytes_to_image(restored_ctr, img_size, img_mode).save(dec_ctr_png)
    with Image.open(dec_ctr_png) as f:
        restored_ctr_from_disk = f.tobytes()

    hash_ctr_ok = sha256(restored_ctr_from_disk) == original_hash

    # Метрики
    hist_data = {"Исходное": raw_pixels}

    ent_orig = calc_entropy(raw_pixels)
    corr_h_orig, corr_v_orig = calc_correlation(orig_np)

    def metrics_for(cipher_bytes: bytes, image_bytes_for_corr: bytes) -> tuple[float, float, float]:
        ent = calc_entropy(cipher_bytes)
        img_np = np.array(bytes_to_image(image_bytes_for_corr, img_size, img_mode))
        ch, cv = calc_correlation(img_np)
        return ent, ch, cv

    ent_xor, ch_xor, cv_xor = metrics_for(cipher_xor, cipher_xor)
    hist_data["Потоковый XOR"] = cipher_xor

    ent_ecb = calc_entropy(cipher_ecb)
    with Image.open(enc_ecb_png) as f:
        ecb_preview = f.tobytes()
    ch_ecb, cv_ecb = calc_correlation(np.array(bytes_to_image(ecb_preview, img_size, img_mode)))
    hist_data["AES-ECB"] = cipher_ecb

    ent_ctr, ch_ctr, cv_ctr = metrics_for(cipher_ctr, cipher_ctr)
    hist_data["AES-CTR"] = cipher_ctr

    # Проверка обратимости (из файлов)
    print(" Проверка обратимости:")
    print(f"    - Потоковый XOR : {'СОВПАДАЕТ' if hash_xor_ok else 'FAIL'}")
    print(f"    - AES-ECB : {'СОВПАДАЕТ' if hash_ecb_ok else 'FAIL'}")
    print(f"    - AES-CTR : {'СОВПАДАЕТ' if hash_ctr_ok else 'FAIL'}")
    print("-" * 78)

    # Сводная таблица
    rows = [
        {"Метод": "Исходное",       "Энтропия": ent_orig, "Corr H": corr_h_orig, "Corr V": corr_v_orig, "Особенности": "Структура изображения"},
        {"Метод": "Потоковый XOR",  "Энтропия": ent_xor,  "Corr H": ch_xor,      "Corr V": cv_xor,      "Особенности": "Сохраняет крупные градиенты/силуэт"},
        {"Метод": "AES-ECB",        "Энтропия": ent_ecb,  "Corr H": ch_ecb,      "Corr V": cv_ecb,      "Особенности": "Сохраняет блочные паттерны"},
        {"Метод": "AES-CTR",        "Энтропия": ent_ctr,  "Corr H": ch_ctr,      "Corr V": cv_ctr,      "Особенности": "Полное перемешивание"},
    ]
    print("\n" + "=" * 90)
    print(f"{'Метод':<15} | {'Энтропия':>10} | {'Corr H':>10} | {'Corr V':>10} | Особенности")
    print("=" * 90)
    for r in rows:
        print(f"{r['Метод']:<15} | {r['Энтропия']:>10.4f} | {r['Corr H']:>10.4f} | {r['Corr V']:>10.4f} | {r['Особенности']}")
    print("=" * 90)

    csv_path = os.path.join("results", f"metrics_{o_name}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["Метод", "Энтропия", "Corr H", "Corr V", "Особенности"])
        w.writeheader()
        w.writerows(rows)

    # Чувствительность к ключу (AES-CTR, 1 бит)
    key_mod = bytearray(aes_key)
    key_mod[0] ^= 0x01
    key_mod = bytes(key_mod)
    cipher_ctr2, _ = aes_ctr_encrypt(raw_pixels, key_mod, nonce)
    npcr, uaci = calc_npcr_uaci(cipher_ctr, cipher_ctr2)
    print(f"\n Чувствительность к ключу:")
    print(f"    NPCR = {npcr:.2f}%   UACI = {uaci:.2f}%")

    # Гистограммы
    hist_path = os.path.join("results", f"histograms_{o_name}.png")
    save_histogram(hist_data, hist_path)

    # meta.json
    meta_path = os.path.join("results", "meta.json")
    meta_by_key: dict[tuple[str, str], dict] = {}
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                for it in data:
                    meta_by_key[(it.get("algorithm"), it.get("source"))] = it
        except json.JSONDecodeError:
            pass

    new_entries = [
        {"algorithm": "xor",     "source": img_name,
         "encrypted_file": enc_xor_png, "decrypted_file": dec_xor_png},
        {"algorithm": "aes-ecb", "source": img_name,
         "encrypted_bin": enc_ecb_bin, "encrypted_preview_png": enc_ecb_png,
         "decrypted_file": dec_ecb_png},
        {"algorithm": "aes-ctr", "source": img_name,
         "nonce": nonce.hex(),
         "encrypted_file": enc_ctr_png, "decrypted_file": dec_ctr_png},
    ]
    for e in new_entries:
        meta_by_key[(e["algorithm"], e["source"])] = e

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(list(meta_by_key.values()), f, indent=4, ensure_ascii=False)

    print(f"\nРезультаты: {csv_path}")
    print(f"Гистограммы: {hist_path}")
    print(f"meta.json: {meta_path}")


if __name__ == "__main__":
    run_lab_experiment()
