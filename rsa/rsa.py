import random
from .miller_rabin import miller_rabin

def gerar_primo(bits=1024):
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1
        if miller_rabin(num):
            return num

def rsa_encrypt(m, pub):
    e, n = pub
    return pow(m, e, n)

def rsa_decrypt(c, priv):
    d, n = priv
    return pow(c, d, n)

def gerar_chaves(bits=1024):
    p = gerar_primo(bits)
    q = gerar_primo(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return (e, n), (d, n)