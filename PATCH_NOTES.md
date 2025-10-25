# Patches aplicados

1) **Assinaturas**: migradas para **RSA-PSS (MGF1/SHA-256)** no módulo `signature.py`.
2) **Assinatura do payload**: agora a assinatura cobre o **payload cifrado + metadados** (encrypted_key, nonce, tag, ciphertext), e **não** o plaintext.
3) **AES-GCM**: nonce de 12 bytes; API padronizada em `crypto.py`.
4) **RSA-OAEP**: uso explícito de MGF1/SHA-256 para encapsular/decapsular a chave de sessão.
5) **app.py (Streamlit)**: atualizado para usar `hybrid_encrypt`/`hybrid_decrypt` com assinatura sobre o payload.
6) **keywrap.py**: utilitário para **envelopar** a chave privada com **PBKDF2-HMAC-SHA256 + AES-GCM** (não integrado por padrão para não quebrar o esquema atual).
7) **Observações**: o banco ainda armazena a chave privada em claro (compatibilidade). Em produção, integrar `keywrap.py` ao `models.py` para proteger a privada, ou não armazená-la.

## Integração futura sugerida
- Alterar `models.insert_user(...)` para salvar a chave privada **envelopada** (`keywrap.wrap_privkey_pem`), pedindo uma senha no cadastro e usando `keywrap.unwrap_privkey_pem` no uso.
- Migrar RSA-2048 para ECC (Curve25519/Ed25519) se desempenho for prioridade.
