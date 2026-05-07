import sys
sys.path.insert(0, ".")

from rsa.rsa import gerar_chaves
from utils.hash_utils import sha3_hash, sign
from utils.base64_utils import encode_base64


pub, priv = gerar_chaves(512)
e, n = pub
d, _ = priv

mensagem = b"Uma vez Flamengo, sempre Flamengo, Flamengo sempre eu hei de ser, eh meu maior prazer, velo brilhar, seja na terra, seja no mar, VENCER VENCER VENCER, uma vez Flamengo, Flamengo ate morrer"

assinatura = sign(mensagem, d, n)
assinatura_b64 = encode_base64(assinatura.to_bytes((assinatura.bit_length() + 7) // 8, "big"))

print("==================================== Assinatura Digital RSA ====================================")
print(f"Mensagem: {mensagem.decode()}")
print("=====================================================================================================")
print(f"Assinatura (Base64): {assinatura_b64}")
print("=====================================================================================================")


h = sha3_hash(mensagem)
h_int = int.from_bytes(h, "big")
verificada = pow(assinatura, e, n) == h_int
print(f"Verificacao: {'VALIDA' if verificada else 'INVALIDA'}")

mensagem_falsa = b"Mensagem adulterada"
h_falsa = sha3_hash(mensagem_falsa)
h_falsa_int = int.from_bytes(h_falsa, "big")
verificada_falsa = pow(assinatura, e, n) == h_falsa_int
print(f"Verificacao (mensagem alterada): {'VALIDA' if verificada_falsa else 'INVALIDA'}")
