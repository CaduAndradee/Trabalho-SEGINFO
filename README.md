# 🔒 Sistema de Mensageria Segura E2E (TLS 1.3 + OAuth 2.0)

Este projeto é uma aplicação de mensageria multi-cliente em Python com foco em segurança máxima. Ele implementa criptografia ponta-a-ponta (E2E), proteção de transporte via TLS 1.3 e autenticação de usuários via Google Identity (OIDC). O servidor atua estritamente como um *blind relay* (retransmissor cego), sendo incapaz de decifrar o conteúdo das mensagens.

Desenvolvido como Trabalho Prático (TP3 e TP4) para a disciplina de Segurança da Informação.

## ✨ Principais Funcionalidades e Garantias de Segurança

* **Confidencialidade e Integridade (E2E):** Criptografia de mensagens usando `AES-128-GCM`.
* **Sigilo Perfeito (Forward Secrecy):** Troca de chaves efêmeras via curva elíptica `X25519` (ECDHE). O comprometimento de chaves futuras não expõe mensagens passadas.
* **Segurança de Transporte:** Canal blindado com `TLS 1.3`, ocultando metadados (como chaves efêmeras e IDs) contra interceptação (MITM).
* **Autenticação Real (OIDC):** Acesso permitido apenas para usuários logados e validados através do `Google OAuth 2.0` (ID Token / JWT).
* **Proteção Anti-Replay e Adulteração:** Uso de contadores monotônicos (`seq_no`) atrelados ao Nonce e tags de autenticação GCM.
* **Certificate Pinning:** Validação rigorosa do certificado da Autoridade Certificadora (Let's Encrypt) pelo cliente.

## 📁 Estrutura do Projeto

* `server.py`: Servidor de roteamento TLS que gerencia conexões e repassa os frames criptografados.
* `client.py`: Cliente de chat E2E com interface de terminal.
* `auth_google_server.py`: Módulo responsável por validar as assinaturas JWT (JWKS do Google) no backend.
* `auth_google_client.py`: Módulo que abre o fluxo de login no navegador para obtenção do ID Token.
* `teste_server_auth.py` / `teste_google.py`: Scripts auxiliares para demonstração de falhas de autenticação.

## 🚀 Pré-requisitos e Instalação

As dependências principais incluem bibliotecas de criptografia e do Google Auth. Instale-as via pip:

```bash
pip install cryptography google-auth google-auth-oauthlib requests