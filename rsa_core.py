"""
Криптографическое ядро RSA для электронной цифровой подписи и шифрования сообщений.
Лабораторная работа: «Разработка схемы динамического пароля. Электронная цифровая подпись».

Включает:
- Генерацию 32-битных простых чисел (модуль N получается 64-битным, как на скриншоте).
- Вычисление ключей RSA (e, d, n).
- Асимметричное шифрование и расшифрование блоков сообщения.
- Хэширование и формирование / проверку электронной цифровой подписи (ЭЦП).
"""

import hashlib
import random
from typing import Tuple, List


def is_prime_miller_rabin(n: int, k: int = 40) -> bool:
    """Тест простоты Миллера-Рабина."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int = 31) -> int:
    """Генерация простого числа заданной битовой длины."""
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime_miller_rabin(p):
            return p


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Расширенный алгоритм Евклида: a*x + b*y = gcd(a, b)"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(e: int, phi: int) -> int:
    """Нахождение мультипликативного обратного e^(-1) mod phi."""
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Мультипликативное обратное не существует (e и phi не взаимно просты).")
    return (x % phi + phi) % phi


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def generate_rsa_keypair(bits: int = 31) -> Tuple[int, int, int]:
    """
    Генерация ключевой пары RSA:
    Возвращает: (e, d, n), где:
      (e, n) - открытый ключ
      (d, n) - секретный ключ
    """
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Выбираем случайную открытую экспоненту e (30-31 бит), взаимно простую с phi
    while True:
        e = random.randrange(2**(bits - 2), 2**bits) | 1
        if gcd(e, phi) == 1:
            break

    d = mod_inverse(e, phi)
    return e, d, n


def encrypt_message(message: str, e_rec: int, n_rec: int) -> List[int]:
    """
    Шифрование сообщения открытым ключом получателя (e_rec, n_rec):
    Каждый символ переводится в код и возводится в степень: C = M^e mod n.
    """
    encoded_bytes = message.encode('utf-8')
    ciphertext_blocks = [pow(b, e_rec, n_rec) for b in encoded_bytes]
    return ciphertext_blocks


def decrypt_message(ciphertext_blocks: List[int], d_rec: int, n_rec: int) -> str:
    """
    Расшифрование сообщения секретным ключом получателя (d_rec, n_rec):
    M = C^d mod n.
    """
    decrypted_bytes = bytearray(pow(c, d_rec, n_rec) for c in ciphertext_blocks)
    return decrypted_bytes.decode('utf-8', errors='replace')


def sign_message(message: str, d_send: int, n_send: int) -> int:
    """
    Формирование электронной цифровой подписи (ЭЦП):
    1. Вычисляется дайджест (хэш) сообщения: h = SHA256(M) mod n_send.
    2. Хэш подписывается секретным ключом отправителя: S = h^d mod n.
    """
    h_int = int(hashlib.sha256(message.encode('utf-8')).hexdigest(), 16) % n_send
    signature = pow(h_int, d_send, n_send)
    return signature


def verify_signature(message: str, signature: int, e_send: int, n_send: int) -> bool:
    """
    Проверка электронной цифровой подписи (ЭЦП):
    1. Вычисляется дайджест h = SHA256(M) mod n_send.
    2. Восстанавливается хэш из подписи открытым ключом отправителя: h' = S^e mod n.
    3. Подпись верна, если h == h'.
    """
    expected_h = int(hashlib.sha256(message.encode('utf-8')).hexdigest(), 16) % n_send
    recovered_h = pow(signature, e_send, n_send)
    return expected_h == recovered_h
