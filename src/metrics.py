import numpy as np
import matplotlib.pyplot as plt

 # Расчет энтропии Шеннона для массива байт
def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    _, counts = np.unique(arr, return_counts=True)
    probabilities = counts / len(arr)
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return float(entropy)

 #Расчет корреляции Пирсона для соседних пикселей
def calc_correlation(image_np: np.ndarray) -> tuple[float, float]:
    np.random.seed(42)

    if len(image_np.shape) == 3:
        img = np.mean(image_np, axis=2).astype(np.float64)
    else:
        img = image_np.astype(np.float64)

    h, w = img.shape

    x1_h = img[:, :-1].flatten()
    x2_h = img[:, 1:].flatten()

    x1_v = img[:-1, :].flatten()
    x2_v = img[1:, :].flatten()

    sample_size = min(10000, len(x1_h))
    idx = np.random.choice(len(x1_h), sample_size, replace=False)

    corr_h = np.corrcoef(x1_h[idx], x2_h[idx])[0, 1]
    corr_v = np.corrcoef(x1_v[idx], x2_v[idx])[0, 1]

    return float(corr_h), float(corr_v)

 # Построение и сохранение гистограмм
def save_histogram(data_dict: dict, save_path: str):
    plt.figure(figsize=(12, 8))
    n = len(data_dict)
    for i, (title, data) in enumerate(data_dict.items(), 1):
        arr = np.frombuffer(data, dtype=np.uint8)
        plt.subplot(2, 2, i)
        plt.hist(arr, bins=256, range=(0, 256), color='black', alpha=0.7, density=True)
        plt.title(f"Гистограмма: {title}")
        plt.xlabel("Значение байта")
        plt.ylabel("Плотность")
        plt.grid(True, linestyle='--', alpha=0.5)

    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close()

 # Расчет чувствительности к ключу NPCR/UACI
def calc_npcr_uaci(cipher1: bytes, cipher2: bytes) -> tuple[float, float]:
    arr1 = np.frombuffer(cipher1, dtype=np.uint8)
    arr2 = np.frombuffer(cipher2, dtype=np.uint8)

    min_len = min(len(arr1), len(arr2))
    arr1, arr2 = arr1[:min_len], arr2[:min_len]

    diff = np.not_equal(arr1, arr2).astype(np.float64)
    npcr = (np.sum(diff) / min_len) * 100.0
    uaci = (np.sum(np.abs(arr1.astype(np.float64) - arr2.astype(np.float64)) / 255.0) / min_len) * 100.0

    return float(npcr), float(uaci)