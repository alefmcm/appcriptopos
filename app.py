import streamlit as st
import base64
import models
from crypto import generate_rsa_keypair, hybrid_encrypt, hybrid_decrypt

st.set_page_config(page_title="Comunicação Segura", layout="centered")
models.init_db()

col1, col2, col3 = st.columns([1,1,1])
with col2:
    st.image("assets/logo.png", width=500)
st.title("Comunicação Segura (RSA-OAEP + AES-GCM + PSS)")

tabs = st.tabs(["Registrar Usuário", "Enviar Mensagem", "Inbox", "Chaves / Export"])

# -------------------- Registrar Usuário --------------------
with tabs[0]:
    st.header("Registrar usuário")
    username = st.text_input("Nome de usuário")
    gen = st.button("Gerar par de chaves")
    if gen and username:
        priv, pub = generate_rsa_keypair()
        models.insert_user(username, pub.decode(), priv.decode())  # NOTE: em produção, proteja a chave privada!
        st.success(f"Usuário {username} registrado.")
    st.write("---")
    user_for_keys = st.text_input("Ver chaves do usuário")
    if st.button("Mostrar chaves") and user_for_keys:
        pub = models.get_public_key(user_for_keys)
        priv = models.get_private_key(user_for_keys)
        if pub:
            st.subheader("Chave pública")
            st.code(pub.decode(), language="pem")
            st.download_button("Download chave pública (PEM)", data=pub, file_name=f"{user_for_keys}_pub.pem")
        if priv:
            st.subheader("Chave privada")
            st.code(priv.decode(), language="pem")
            st.warning("Demonstração: chave privada exposta. Em produção, cifre com senha ou não armazene no servidor.")
            st.download_button("Download chave privada (PEM)", data=priv, file_name=f"{user_for_keys}_priv.pem")

# -------------------- Enviar Mensagem --------------------
with tabs[1]:
    st.header("Enviar mensagem")
    sender = st.text_input("Remetente")
    recipient = st.text_input("Destinatário")
    message = st.text_area("Mensagem (plaintext)")

    if st.button("Enviar"):
        s_priv = models.get_private_key(sender)
        r_pub = models.get_public_key(recipient)
        if not s_priv or not r_pub:
            st.error("Verifique se remetente e destinatário existem e possuem chaves.")
        else:
            payload_bytes, signature_b64 = hybrid_encrypt(s_priv, r_pub, message.encode())
            models.store_message(sender, recipient, payload_bytes, signature_b64)
            st.success("Mensagem enviada com sucesso (payload assinado + cifrado).")

# -------------------- Inbox --------------------
with tabs[2]:
    st.header("Inbox")
    who = st.text_input("Usuário (destinatário)")
    if st.button("Listar mensagens"):
        rows = models.list_messages_for(who)
        if not rows:
            st.info("Nenhuma mensagem.")
        else:
            for mid, sender, payload, signature, ts in rows:
                st.markdown(f"### Mensagem #{mid} — de **{sender}**")
                s_pub = models.get_public_key(sender)
                r_priv = models.get_private_key(who)
                if not s_pub or not r_priv:
                    st.error("Chaves ausentes para verificar/decifrar.")
                    continue
                try:
                    plaintext = hybrid_decrypt(r_priv, s_pub, payload, signature).decode(errors="replace")
                    st.code(plaintext)
                    st.caption("Assinatura verificada e payload decifrado com sucesso.")
                except Exception as e:
                    st.error(f"Falha ao verificar/decifrar: {e}")

# -------------------- Chaves / Export --------------------
with tabs[3]:
    st.header("Exportar chaves")
    who = st.text_input("Usuário para exportar")
    if st.button("Exportar"):
        pub = models.get_public_key(who)
        priv = models.get_private_key(who)
        if pub:
            st.download_button("Baixar chave pública (PEM)", data=pub, file_name=f"{who}_pub.pem")
        if priv:
            st.download_button("Baixar chave privada (PEM)", data=priv, file_name=f"{who}_priv.pem")
    st.info("Recomendação: proteger a chave privada com PBKDF2/Argon2 + AES-GCM ou não armazená-la no servidor.")
