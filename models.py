# models.py
import sqlite3
from pathlib import Path

# Caminho do banco de dados SQLite
DB = Path(__file__).parent / "messages.db"

def init_db():
    """Inicializa o banco de dados e cria as tabelas, se não existirem."""
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            public_key TEXT,
            private_key TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            sender TEXT,
            recipient TEXT,
            payload BLOB,
            signature TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def add_user(username: str, public_key_pem, private_key_pem):
    """Adiciona (ou substitui) um usuário com suas chaves RSA no banco."""
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    pub = public_key_pem.decode() if isinstance(public_key_pem, (bytes, bytearray)) else public_key_pem
    priv = private_key_pem.decode() if isinstance(private_key_pem, (bytes, bytearray)) else private_key_pem
    c.execute('INSERT OR REPLACE INTO users (username, public_key, private_key) VALUES (?,?,?)',
              (username, pub, priv))
    conn.commit()
    conn.close()

# Compatibilidade retroativa (para códigos antigos)
insert_user = add_user

def get_public_key(username: str):
    """Retorna a chave pública de um usuário."""
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT public_key FROM users WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    return row[0].encode() if row else None

def get_private_key(username: str):
    """Retorna a chave privada de um usuário."""
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT private_key FROM users WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    return row[0].encode() if row else None

def list_users():
    """Lista todos os usuários cadastrados."""
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT username FROM users ORDER BY username COLLATE NOCASE')
    rows = [r[0] for r in c.fetchall()]
    conn.close()
    return rows

def store_message(sender: str, recipient: str, payload_bytes: bytes, signature_b64: str):
    """Armazena mensagem cifrada e assinada no banco."""
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('INSERT INTO messages (sender, recipient, payload, signature) VALUES (?,?,?,?)',
              (sender, recipient, sqlite3.Binary(payload_bytes), signature_b64))
    conn.commit()
    conn.close()

def list_messages_for(user: str):
    """Lista mensagens destinadas a determinado usuário."""
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT id, sender, payload, signature, timestamp FROM messages WHERE recipient=? ORDER BY id DESC', (user,))
    rows = c.fetchall()
    conn.close()
    return rows
