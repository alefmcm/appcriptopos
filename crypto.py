import base64, json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from signature import sign_pss, verify_pss

def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key.export_key(), key.publickey().export_key()

def sha256_digest(data: bytes):
    return SHA256.new(data)

def rsa_encrypt_oaep(pub_pem: bytes, data: bytes) -> bytes:
    key = RSA.import_key(pub_pem)
    return PKCS1_OAEP.new(key, hashAlgo=SHA256).encrypt(data)

def rsa_decrypt_oaep(priv_pem: bytes, data: bytes) -> bytes:
    key = RSA.import_key(priv_pem)
    return PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(data)

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b""):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad: cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ct, tag

def aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad: cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)

def b64e(b: bytes) -> str: return base64.b64encode(b).decode()
def b64d(s: str) -> bytes: return base64.b64decode(s, validate=True)

def build_payload(encrypted_key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> dict:
    """Canonical JSON-serializable payload (without signature)."""
    return {
        "v": 1,
        "encrypted_key": b64e(encrypted_key),
        "nonce": b64e(nonce),
        "tag": b64e(tag),
        "ciphertext": b64e(ciphertext),
    }

def sign_payload(priv_pem: bytes, payload_obj: dict) -> str:
    payload_bytes = json.dumps(payload_obj, separators=(",",":"), sort_keys=True).encode()
    return sign_pss(priv_pem, payload_bytes)

def verify_payload_signature(pub_pem: bytes, payload_obj: dict, signature_b64: str) -> bool:
    payload_bytes = json.dumps(payload_obj, separators=(",",":"), sort_keys=True).encode()
    return verify_pss(pub_pem, payload_bytes, signature_b64)

def hybrid_encrypt(sender_priv_pem: bytes, receiver_pub_pem: bytes, plaintext: bytes):
    """Return (payload_bytes, signature_b64) ready to store/transmit. Signature covers the payload."""
    k = get_random_bytes(32)  # AES-256
    nonce, ct, tag = aes_gcm_encrypt(k, plaintext)
    enc_k = rsa_encrypt_oaep(receiver_pub_pem, k)
    payload = build_payload(enc_k, nonce, tag, ct)
    sig = sign_payload(sender_priv_pem, payload)
    payload_bytes = json.dumps(payload, separators=(",",":"), sort_keys=True).encode()
    return payload_bytes, sig

def hybrid_decrypt(receiver_priv_pem: bytes, sender_pub_pem: bytes, payload_bytes: bytes, signature_b64: str) -> bytes:
    """Verify signature over payload, then decrypt OAEP key and AES-GCM ciphertext."""
    payload = json.loads(payload_bytes.decode())
    if not verify_payload_signature(sender_pub_pem, payload, signature_b64):
        raise ValueError("Assinatura inválida para o payload.")
    enc_k = b64d(payload["encrypted_key"])
    nonce = b64d(payload["nonce"])
    tag = b64d(payload["tag"])
    ct = b64d(payload["ciphertext"])
    k = rsa_decrypt_oaep(receiver_priv_pem, enc_k)
    return aes_gcm_decrypt(k, nonce, ct, tag)
