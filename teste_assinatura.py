import os

from rsa.rsa import gerar_chaves, rsa_cifrar_oaep, rsa_decifrar_oaep, rsa_decrypt
from utils.signed_document import (
    verificar_documento,
    assinar_arquivo,
    verificar_arquivo,
    salvar_assinatura,
)
from utils.hash_utils import sha3_hash

BITS = 1024
ARQUIVO_TESTE = "arquivo_teste.txt"

print("========================================")
print("\n[1] Geracao de chaves RSA (Miller-Rabin)...")
pub, priv = gerar_chaves(BITS)
e, n = pub
d, _ = priv
print(f"    Primo p: {BITS} bits")
print(f"    Primo q: {BITS} bits")
print(f"    Modulo n: {n.bit_length()} bits")
print(f"    Expoente publico e: {e}")
print(f"    Expoente privado d: {d.bit_length()} bits\n")

print("========================================")
print("\n[2] Cifracao e decifracao RSA com OAEP...")
msg_teste = b"mensagem de teste"
cifrado = rsa_cifrar_oaep(msg_teste, pub)
decifrado = rsa_decifrar_oaep(cifrado, priv)
print(f"    Mensagem original: {msg_teste}")
print(f"    Mensagem cifrada: {cifrado}")
print(f"    Mensagem decifrada: {decifrado}")
print(f"    OAEP: {'SUCESSO' if msg_teste == decifrado else 'FALHA'}\n")

# Cria arquivo de teste
print("========================================")
conteudo = b'''\nUma vez Flamengo\nSempre Flamengo\nFlamengo sempre eu hei de ser\n\nEh meu maior prazer ve-lo brilhar\nSeja na terra, seja no mar\nVencer, vencer, vencer\n\nUma vez Flamengo\nFlamengo ate morrer'''
with open(ARQUIVO_TESTE, "wb") as f:
    f.write(conteudo)
print(f"[3] Arquivo de teste criado: '{ARQUIVO_TESTE}'")
print(f"    Conteudo: \n{conteudo.decode()}\n")

# Calcula hash
hash_msg = sha3_hash(conteudo)
print(f"[4] Calculo do hash SHA3-256 da mensagem...")
print(f"    Hash: {hash_msg.hex()}\n")

# Assina o arquivo
print("[5] Assinando arquivo (cifrao do hash com chave privada)...")
doc_assinado = assinar_arquivo(ARQUIVO_TESTE, priv)
salvar_assinatura(doc_assinado, "arquivo_teste.assinado")
print(f"    Documento assinado:\n")
print(f"{doc_assinado}\n")
print(f"    Documento salvo em: 'arquivo_teste.assinado'\n")


# Parsing do documento
print("========================================")
print("\n[6] Parsing do documento assinado (Base64 -> dados + assinatura)...")
from utils.signed_document import parsear_documento_assinado
mensagem_extraida, assinatura_extraida = parsear_documento_assinado(doc_assinado)
print(f"    Mensagem extraida: \n{mensagem_extraida.decode()}\n")
print(f"    Tamanho da assinatura: {assinatura_extraida.bit_length()} bits\n")


# Decifracao da assinatura
print("[7] Decifracao da assinatura (recuperacao do hash cifrado)...")
em_len = (n.bit_length() - 1 + 7) // 8
em_int = rsa_decrypt(assinatura_extraida, priv)
print(f"    Hash decifrado: {em_int.bit_length()} bits\n")

# Verificacao com documento original
print("[8] Verificacao do documento original...")
valido, mensagem_recuperada = verificar_arquivo("arquivo_teste.assinado", pub)
print(f"    Mensagem recuperada: \n{mensagem_recuperada.decode()}\n")
print(f"    Resultado: {'ASSINATURA VALIDA' if valido else 'ASSINATURA INVALIDA'}\n")

# Verificacao com documento adulterado
print("[9] Verificacao com documento adulterado...")
from utils.base64_utils import encode_base64
dados_originais = parsear_documento_assinado(doc_assinado)
msg_falsa_sig = b"Conteudo adulterado e diferente do original!" + b"||RSA_SIG||" + dados_originais[1].to_bytes((dados_originais[1].bit_length() + 7) // 8, "big")
doc_adulterado_final = encode_base64(msg_falsa_sig)
valido_falso, _ = verificar_documento(doc_adulterado_final, pub)
print(f"    Resultado: {'ASSINATURA VALIDA' if valido_falso else 'ASSINATURA INVALIDA (correto!)'}\n")

# Comparacao manual do hash
print("[10] Verificacao manual (calculo e comparacao do hash)...")
hash_calculado = sha3_hash(mensagem_recuperada)
print(f"    Hash calculado:  {hash_calculado.hex()}")
print(f"    Hash original:   {hash_msg.hex()}")
print(f"    Hashes iguais: {hash_calculado == hash_msg}\n")
print("========================================")


# Limpeza
os.remove(ARQUIVO_TESTE)
os.remove("arquivo_teste.assinado")