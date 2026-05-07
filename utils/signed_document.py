from rsa.rsa import rsa_cifrar_oaep, rsa_decifrar_oaep
from utils.hash_utils import sign, verify
from utils.base64_utils import encode_base64, decode_base64

SEPARATOR = b"||RSA_SIG||"

def criar_documento_assinado(mensagem_bytes, assinatura):
    sig_bytes = assinatura.to_bytes((assinatura.bit_length() + 7) // 8, "big")
    documento = mensagem_bytes + SEPARATOR + sig_bytes
    return encode_base64(documento)

def parsear_documento_assinado(doc_base64):
    dados = decode_base64(doc_base64)
    partes = dados.split(SEPARATOR)
    if len(partes) != 2:
        raise ValueError("Formato de documento assinado invalido")
    mensagem = partes[0]
    assinatura = int.from_bytes(partes[1], "big")
    return mensagem, assinatura

def assinar_documento(mensagem_bytes, priv):
    d, n = priv
    assinatura = sign(mensagem_bytes, d, n)
    return criar_documento_assinado(mensagem_bytes, assinatura)

def verificar_documento(doc_base64, pub):
    e, n = pub
    mensagem, assinatura = parsear_documento_assinado(doc_base64)
    valido = verify(mensagem, assinatura, e, n)
    return valido, mensagem

def cifrar_mensagem(mensagem_bytes, pub):
    c = rsa_cifrar_oaep(mensagem_bytes, pub)
    return encode_base64(c.to_bytes((c.bit_length() + 7) // 8, "big"))

def decifrar_mensagem(cifrado_base64, priv):
    cifrado_bytes = decode_base64(cifrado_base64)
    c = int.from_bytes(cifrado_bytes, "big")
    rsa_decifrar_oaep(c, priv)

def assinar_arquivo(caminho_arquivo, priv):
    with open(caminho_arquivo, "rb") as f:
        dados = f.read()
    return assinar_documento(dados, priv)

def verificar_arquivo(caminho_assinatura, pub):
    with open(caminho_assinatura, "r") as f:
        doc_base64 = f.read().strip()
    return verificar_documento(doc_base64, pub)

def salvar_assinatura(doc_base64, caminho_saida):
    with open(caminho_saida, "w") as f:
        f.write(doc_base64)
