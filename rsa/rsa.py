import secrets
import hashlib
from .miller_rabin import miller_rabin

HASH_LEN = 32

def _mgf1(seed, length):
    mask = b""
    counter = 0
    while len(mask) < length:
        mask += hashlib.sha3_256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return mask[:length]

def _codificar_oaep(m, n_bits):
    k = (n_bits + 7) // 8
    m_hash = hashlib.sha3_256(b"").digest()
    ps_len = k - len(m) - 2 * HASH_LEN - 2
    if ps_len < 0:
        raise ValueError("Mensagem muito longa")
    db = m_hash + b"\x00" * ps_len + b"\x01" + m
    seed = secrets.randbits(HASH_LEN * 8).to_bytes(HASH_LEN, "big")
    db_mask = _mgf1(seed, len(db))
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = _mgf1(masked_db, HASH_LEN)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db

def _decodificar_oaep(em, n_bits):
    k = (n_bits + 7) // 8
    m_hash = hashlib.sha3_256(b"").digest()
    masked_seed = em[1:HASH_LEN + 1]
    masked_db = em[HASH_LEN + 1:]
    seed_mask = _mgf1(masked_db, HASH_LEN)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = _mgf1(seed, len(masked_db))
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    db_hash = db[:HASH_LEN]
    if db_hash != m_hash:
        raise ValueError("Falha na decifracao OAEP: incompatibilidade de hash do rotulo")
    i = HASH_LEN
    while i < len(db) and db[i] == 0:
        i += 1
    if i >= len(db) or db[i] != 1:
        raise ValueError("Falha na decifracao OAEP: separador 0x01 nao encontrado")
    return db[i + 1:]

def gerar_primo(bits=1024):
    while True:
        num = secrets.randbits(bits)
        num |= (1 << bits - 1) | 1
        if miller_rabin(num):
            return num

def rsa_encrypt(m, pub):
    e, n = pub
    return pow(m, e, n)

def rsa_decrypt(c, priv):
    d, n = priv
    return pow(c, d, n)

def rsa_cifrar_oaep(mensagem_bytes, pub):
    e, n = pub
    em = _codificar_oaep(mensagem_bytes, n.bit_length())
    m_int = int.from_bytes(em, "big")
    return pow(m_int, e, n)

def rsa_decifrar_oaep(cifrado_int, priv):
    d, n = priv
    m_int = pow(cifrado_int, d, n)
    em_len = (n.bit_length() + 7) // 8
    em = m_int.to_bytes(em_len, "big")
    return _decodificar_oaep(em, n.bit_length())

def gerar_chaves(bits=1024):
    p = gerar_primo(bits)
    q = gerar_primo(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return (e, n), (d, n)
