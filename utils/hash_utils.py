import hashlib

def sha3_hash(data):
    return hashlib.sha3_256(data).digest()

def sign(message, d, n):
    h = sha3_hash(message)
    h_int = int.from_bytes(h, 'big')
    sig = pow(h_int, d, n)
    return sig