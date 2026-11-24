import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class Xorshift32:
    """Простой потоковый ПСЧ. seed приводится к 32-битному ненулевому состоянию."""
    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFF
        if self.state == 0:
            self.state = 1

    def next_byte(self) -> int:
        x = self.state
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        self.state = x
        return x & 0xFF


def xor_encrypt_decrypt(data: bytes, key_int: int) -> bytes:
    """Один и тот же вызов и для шифрования, и для дешифрования."""
    prng = Xorshift32(key_int)
    return bytes(b ^ prng.next_byte() for b in data)


def aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes_ctr_encrypt(data: bytes, key: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    if nonce is None:
        nonce = os.urandom(16)
    if len(nonce) != 16:
        raise ValueError("Для AES-CTR требуется nonce длиной 16 байт")
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize(), nonce


def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(nonce) != 16:
        raise ValueError("Для AES-CTR требуется nonce длиной 16 байт")
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()