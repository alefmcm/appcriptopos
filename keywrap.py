import base64, json
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)

def wrap_privkey_pem(priv_pem: bytes, passphrase: str, iterations: int = 200_000) -> str:
    """Encrypt a PEM private key with AES-GCM using a key derived from passphrase via PBKDF2-HMAC-SHA256."""
    salt = get_random_bytes(16)
    key = PBKDF2(passphrase, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(priv_pem)
    blob = {
        "kdf": "PBKDF2-HMAC-SHA256", "iter": iterations,
        "salt": b64e(salt), "nonce": b64e(cipher.nonce), "tag": b64e(tag), "ct": b64e(ct)
    }
    return json.dumps(blob, separators=(",",":"))

def unwrap_privkey_pem(blob_json: str, passphrase: str) -> bytes:
    """Decrypt a wrapped private key JSON with passphrase."""
    b = json.loads(blob_json)
    key = PBKDF2(passphrase, base64.b64decode(b["salt"]), dkLen=32,
                 count=int(b["iter"]), hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM, nonce=b64d(b["nonce"]))
    return cipher.decrypt_and_verify(b64d(b["ct"]), b64d(b["tag"]))
