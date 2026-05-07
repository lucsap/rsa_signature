# 🔐 Gerador e Verificador de Assinaturas RSA

> Trabalho 2 de Segurança Computacional da Universidade de Brasília (UnB) 🎓

## 📋 Sobre

Implementação completa de um sistema de **assinatura digital RSA** em Python 🐍. O projeto gera chaves RSA, assina arquivos com hash SHA-3 e permite verificar a autenticidade de documentos assinados.

## 📁 Estrutura

```
rsa_signature/
├── rsa/
│   ├── miller_rabin.py      # Teste de primalidade Miller-Rabin
│   └── rsa.py               # Geração de chaves, OAEP, cifração/decifração
├── utils/
│   ├── base64_utils.py      # Codificação/decodificação BASE64
│   ├── hash_utils.py        # Hash SHA3-256, assinatura e verificação
├── teste_rsa.py
├── teste_assinatura.py
└── README.md
```

## 🚀 Como Usar

```bash
# Teste de assinaturas
python teste_assinatura.py

# Teste RSA
python teste_rsa.py
```
