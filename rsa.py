
import secrets

MAX_CHAR_CODE = 1114111

def mod_pow(base, exp, m):
    if m <= 0:
        raise ValueError("Invalid modulus")
    if exp < 0:
        raise ValueError("Invalid exponent")

    result = 1
    base = base % m

    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % m
        base = (base * base) % m
        exp = exp // 2

    return result % m


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    if gcd(e, phi) != 1:
        raise ValueError("No inverse found")

    for i in range(1, e + 1):
        if (phi * i + 1) % e == 0:
            return (phi * i + 1) // e

    raise ValueError("No inverse found")


def is_prime(n, rounds=20):
    if n < 2:
        return False

    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n == p:
            return True
        if n % p == 0:
            return False

    s = 0
    d = n - 1

    while d % 2 == 0:
        d = d // 2
        s += 1

    for i in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = mod_pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for j in range(s - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits):
    if bits < 2:
        raise ValueError("Invalid bit size")

    while True:
        n = secrets.randbits(bits)
        n = n | (1 << (bits - 1)) | 1

        if is_prime(n):
            return n


def generate_keys(bits=16):
    if bits < 11 or bits > 512:
        raise ValueError("Prime size must be between 11 and 512")

    while True:
        p = generate_prime(bits)
        q = generate_prime(bits)

        if p == q:
            continue
        n = p * q
        if n <= MAX_CHAR_CODE:
            continue

        phi = (p - 1) * (q - 1)

        e = 65537
        if e >= phi or gcd(e, phi) != 1:
            e = 3
            while e < phi and gcd(e, phi) != 1:
                e += 2

        if e >= phi:
            continue

        d = mod_inverse(e, phi)
        return {"p":p,"q":q,"n":n,"phi":phi,"e":e,"d":d}


def encrypt_text(text, e, n):
    if not isinstance(text, str) or not text:
        raise ValueError("Enter text first")

    if n <= MAX_CHAR_CODE:
        raise ValueError("Key is too small")

    if e <= 1 or e >= n:
        raise ValueError("Invalid public key")

    encrypted = []

    for char in text:
        number = ord(char)
        cipher = mod_pow(number, e, n)
        encrypted.append(str(cipher))

    return " ".join(encrypted)


def decrypt_text(cipher, d, n):
    if not isinstance(cipher, str) or not cipher.strip():
        raise ValueError("Enter encrypted text")

    if n <= MAX_CHAR_CODE or d <= 1 or d >= n:
        raise ValueError("Invalid private key")

    decrypted = []

    for part in cipher.split():
        if not part.isascii() or not part.isdigit():
            raise ValueError("Invalid ciphertext")

        c = int(part)

        if c >= n:
            raise ValueError("Invalid ciphertext")

        number = mod_pow(c, d, n)

        if number > MAX_CHAR_CODE:
            raise ValueError("Wrong key or ciphertext")

        if 0xD800 <= number <= 0xDFFF:
            raise ValueError("Invalid decrypted character")

        decrypted.append(chr(number))

    return "".join(decrypted)


def parse_key(text):
    if not isinstance(text, str):
        raise ValueError("Invalid key")

    parts = text.replace(",", " ").split()

    if len(parts) != 2:
        raise ValueError("Enter two key numbers")

    if not all(p.isascii() and p.isdigit() for p in parts):
        raise ValueError("Invalid key")

    a, n = map(int, parts)

    if a <= 1 or n <= MAX_CHAR_CODE or a >= n:
        raise ValueError("Invalid key values")

    return a, n
