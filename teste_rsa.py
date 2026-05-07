from rsa.rsa import gerar_chaves, rsa_encrypt, rsa_decrypt

print("=== Teste RSA Base (sem OAEP) ===")
bits = int(input("Digite o numero de bits para p e q: "))
pub, priv = gerar_chaves(bits)
e, n = pub
d, _ = priv

print(f"Chave publica gerada: e={e}, n={n.bit_length()} bits")

mensagem = int(input("Digite um numero inteiro para cifrar: "))
cifrado = rsa_encrypt(mensagem, pub)
decifrado = rsa_decrypt(cifrado, priv)

print(f"Mensagem original: {mensagem}")
print(f"Mensagem cifrada: {cifrado}")
print(f"Mensagem decifrada: {decifrado}")
print(f"Funcionou: {mensagem == decifrado}")
