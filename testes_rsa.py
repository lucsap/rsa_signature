import sys

sys.path.insert(0, "rsa")
from rsa import gerar_primo, rsa_encrypt, rsa_decrypt

print("=== Teste (1024 bits) ===")
bits = int(input("Digite o numero de bits: "))
p = gerar_primo(bits)
q = gerar_primo(bits)
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)

mensagem = int(input("Digite um numero: "))
cifrado = rsa_encrypt(mensagem, (e, n))
decifrado = rsa_decrypt(cifrado, (d, n))

print(f"p = {p}")
print(f"q = {q}")
print(f"n = {n}")
print(f"Mensagem original: {mensagem}")
print(f"Mensagem cifrada: {cifrado}")
print(f"Mensagem decifrada: {decifrado}")
print(f"Funcionou: {mensagem == decifrado}")
