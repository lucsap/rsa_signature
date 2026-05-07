import hashlib
import os

HASH_LEN = 32

def sha3_hash(data):
    return hashlib.sha3_256(data).digest()

def _mgf1(seed, length):
    mask = b""
    counter = 0
    while len(mask) < length:
        mask += hashlib.sha3_256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return mask[:length]

def _codificar_emsa_pss(message, em_bits):
    em_len = (em_bits + 7) // 8
    m_hash = sha3_hash(message)
    salt = os.urandom(HASH_LEN)
    m_prime = b"\x00" * 8 + m_hash + salt
    h = sha3_hash(m_prime)
    ps_len = em_len - HASH_LEN - HASH_LEN - 2
    if ps_len < 0:
        raise ValueError("Mensagem muito longa")
    db = b"\x00" * ps_len + b"\x01" + salt
    db_mask = _mgf1(h, len(db))
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    bits_to_clear = 8 * em_len - em_bits
    if bits_to_clear > 0:
        masked_db = bytes([masked_db[0] & (0xFF >> bits_to_clear)]) + masked_db[1:]
    return masked_db + h + b"\xbc"

def _verificar_emsa_pss(message, em, em_bits):
    em_len = len(em)
    if em[-1] != 0xBC:
        return False
    h = em[em_len - HASH_LEN - 1:em_len - 1]
    masked_db = em[:em_len - HASH_LEN - 1]
    db_mask = _mgf1(h, len(masked_db))
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    bits_to_clear = 8 * em_len - em_bits
    if bits_to_clear > 0:
        db = bytes([db[0] & (0xFF >> bits_to_clear)]) + db[1:]
    sep_idx = db.index(b"\x01")
    salt = db[sep_idx + 1:]
    m_prime = b"\x00" * 8 + sha3_hash(message) + salt
    h_prime = sha3_hash(m_prime)
    return h == h_prime

def sign(message, d, n):
    em_bits = n.bit_length() - 1
    em = _codificar_emsa_pss(message, em_bits)
    em_int = int.from_bytes(em, "big")
    sig = pow(em_int, d, n)
    return sig

def verify(message, signature, e, n):
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    em_int = pow(signature, e, n)
    em = em_int.to_bytes(em_len, "big")
    return _verificar_emsa_pss(message, em, em_bits)
