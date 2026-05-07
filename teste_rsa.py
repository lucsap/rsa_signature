import sys
from rsa.rsa import gerar_chaves, rsa_encrypt, rsa_decrypt

print("=== Teste (1024 bits) ===")
bits = int(input("Digite o numero de bits: "))
pub, priv = gerar_chaves(bits)

mensagem = int(input("Digite um numero: "))
cifrado = rsa_encrypt(mensagem, pub)
decifrado = rsa_decrypt(cifrado, priv)

print(f"Mensagem original: {mensagem}")
print(f"Mensagem cifrada: {cifrado}")
print(f"Mensagem decifrada: {decifrado}")
print(f"Funcionou: {mensagem == decifrado}")