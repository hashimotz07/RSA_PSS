import random
from math import gcd

def eh_primo(n, k=40):
    #Teste de primalidade de Miller-Rabin
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    #Escreve n-1 como 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gera_primo_grande(bits):
    #Gera um numero primo grande
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # garante que tem `bits` bits e é ímpar
        if eh_primo(p):
            return p

def modinv(a, m):
    #Inverso modular usando o algoritmo extendido de Euclides
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception('Inverso modular não existe')
    return x % m

def extended_gcd(a, b):
    #Algoritmo de Euclides extendido
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y

def generate_rsa_keys(bits=2048):
    #Gera par de chaves RSA com primos de tamanho `bits`/2
    print("Gerando primos...")
    p = gera_primo_grande(bits // 2)
    q = gera_primo_grande(bits // 2)
    while q == p:
        q = gera_primo_grande(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = modinv(e, phi)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key