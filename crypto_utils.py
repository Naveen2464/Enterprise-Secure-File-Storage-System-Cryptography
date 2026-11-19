"""Educational hybrid file encryption helpers.

Uses AES-256-GCM (authenticated encryption), RSA-OAEP/SHA-256 for key wrapping,
SHA-256 for a plaintext digest, and RSA-PSS/SHA-256 for package signatures.
"""
import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT_VERSION = 1
AES_KEY_BYTES = 32
NONCE_BYTES = 12


def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def load_public_key(pem_bytes):
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Expected an RSA public key.")
    return key


def load_private_key(pem_bytes):
    key = serialization.load_pem_private_key(pem_bytes, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Expected an RSA private key.")
    return key


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _unb64(value):
    return base64.b64decode(value.encode("ascii"), validate=True)


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _signed_content(envelope):
    """Signature covers all envelope fields except the signature itself."""
    return _canonical({k: v for k, v in envelope.items() if k != "signature"})


def encrypt_file(filename, plaintext, recipient_public_pem, sender_private_pem):
    recipient_public = load_public_key(recipient_public_pem)
    sender_private = load_private_key(sender_private_pem)

    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_BYTES)
    safe_name = os.path.basename(filename) or "download.bin"
    digest = hashlib.sha256(plaintext).hexdigest()

    # Bind version and filename as authenticated metadata.
    aad = _canonical({"version": FORMAT_VERSION, "filename": safe_name})
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext, aad)

    wrapped_key = recipient_public.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    envelope = {
        "version": FORMAT_VERSION,
        "filename": safe_name,
        "algorithm": "AES-256-GCM",
        "key_wrap": "RSA-OAEP-SHA256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "nonce": _b64(nonce),
        "wrapped_key": _b64(wrapped_key),
        "ciphertext": _b64(ciphertext),
        "sha256": digest,
    }
    signature = sender_private.sign(
        _signed_content(envelope),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    envelope["signature"] = _b64(signature)
    return _canonical(envelope)


def _parse_package(package_bytes):
    envelope = json.loads(package_bytes.decode("utf-8"))
    required = {"version", "filename", "algorithm", "key_wrap",
                "signature_algorithm", "nonce", "wrapped_key",
                "ciphertext", "sha256", "signature"}
    if set(envelope) != required:
        raise ValueError("Invalid package structure.")
    if envelope["version"] != FORMAT_VERSION:
        raise ValueError("Unsupported file format version.")
    if envelope["algorithm"] != "AES-256-GCM":
        raise ValueError("Unsupported encryption algorithm.")
    return envelope


def verify_package_signature(package_bytes, sender_public_pem):
    envelope = _parse_package(package_bytes)
    sender_public = load_public_key(sender_public_pem)
    try:
        sender_public.verify(
            _unb64(envelope["signature"]),
            _signed_content(envelope),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def decrypt_file(package_bytes, recipient_private_pem, sender_public_pem):
    envelope = _parse_package(package_bytes)
    if not verify_package_signature(package_bytes, sender_public_pem):
        raise ValueError("Digital signature verification failed.")

    recipient_private = load_private_key(recipient_private_pem)
    session_key = recipient_private.decrypt(
        _unb64(envelope["wrapped_key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(session_key) != AES_KEY_BYTES:
        raise ValueError("Invalid AES session key length.")

    aad = _canonical({"version": envelope["version"], "filename": envelope["filename"]})
    plaintext = AESGCM(session_key).decrypt(
        _unb64(envelope["nonce"]), _unb64(envelope["ciphertext"]), aad
    )
    actual_digest = hashlib.sha256(plaintext).hexdigest()
    if actual_digest != envelope["sha256"]:
        raise ValueError("SHA-256 integrity check failed.")

    # basename prevents path traversal when the downloaded filename is used.
    return os.path.basename(envelope["filename"]), plaintext
