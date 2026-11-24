import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    _, counts = np.unique(arr, return_counts=True)
    p = counts / len(arr)
    return float(-np.sum(p * np.log2(p)))


def calc_correlation(image_np: np.ndarray) -> tuple[float, float]:
    if image_np.ndim == 3:
        img = np.mean(image_np, axis=2).astype(np.float64)
    else:
        img = image_np.astype(np.float64)

    x1_h = img[:, :-1].ravel()
    x2_h = img[:, 1:].ravel()
    x1_v = img[:-1, :].ravel()
    x2_v = img[1:, :].ravel()

    n_h = min(10000, x1_h.size)
    n_v = min(10000, x1_v.size)

    rng_h = np.random.default_rng(42)
    rng_v = np.random.default_rng(43)

    idx_h = rng_h.choice(x1_h.size, n_h, replace=False)
    idx_v = rng_v.choice(x1_v.size, n_v, replace=False)

    corr_h = float(np.corrcoef(x1_h[idx_h], x2_h[idx_h])[0, 1])
    corr_v = float(np.corrcoef(x1_v[idx_v], x2_v[idx_v])[0, 1])
    return corr_h, corr_v


def save_histogram(data_dict: dict, save_path: str):
    plt.figure(figsize=(12, 8))
    for i, (title, data) in enumerate(data_dict.items(), 1):
        arr = np.frombuffer(data, dtype=np.uint8)
        plt.subplot(2, 2, i)
        plt.hist(arr, bins=256, range=(0, 256), color="black", alpha=0.7, density=True)
        plt.title(f"Гистограмма: {title}")
        plt.xlabel("Значение байта")
        plt.ylabel("Плотность")
        plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close()


def calc_npcr_uaci(cipher1: bytes, cipher2: bytes) -> tuple[float, float]:
    a1 = np.frombuffer(cipher1, dtype=np.uint8).astype(np.float64)
    a2 = np.frombuffer(cipher2, dtype=np.uint8).astype(np.float64)
    n = min(a1.size, a2.size)
    a1, a2 = a1[:n], a2[:n]
    npcr = float(np.sum(a1 != a2) / n * 100.0)
    uaci = float(np.sum(np.abs(a1 - a2) / 255.0) / n * 100.0)
    return npcr, uaci