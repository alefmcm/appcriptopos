import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

def sign_pss(priv_pem: bytes, data: bytes) -> str:
    """Sign arbitrary bytes using RSA-PSS (MGF1/SHA-256). Returns base64 signature string."""
    key = RSA.import_key(priv_pem)
    h = SHA256.new(data)
    sig = pss.new(key).sign(h)
    return base64.b64encode(sig).decode()

def verify_pss(pub_pem: bytes, data: bytes, sig_b64: str) -> bool:
    """Verify RSA-PSS signature (base64)."""
    key = RSA.import_key(pub_pem)
    h = SHA256.new(data)
    try:
        sig = base64.b64decode(sig_b64, validate=True)
        pss.new(key).verify(h, sig)
        return True
    except Exception:
        return False
