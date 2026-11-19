"""OpenSSL CLI integration utilities.

Directly bridges Python with the system OpenSSL binary to execute
real-time cryptographic inspections, digital signatures, hashing, and encryption.
"""
import os
import shutil
import subprocess
import tempfile
from typing import Optional, Tuple


def get_openssl_executable() -> str:
    """Locate the OpenSSL binary on PATH or common installation locations."""
    # 1. System PATH
    found = shutil.which("openssl")
    if found:
        return found

    # 2. Common Windows paths (Git, Chocolatey, Win64OpenSSL)
    candidates = [
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files (x86)\Git\usr\bin\openssl.exe",
        r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        r"C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path

    raise FileNotFoundError(
        "OpenSSL binary not found. Please ensure OpenSSL or Git for Windows is installed."
    )


def get_openssl_version() -> str:
    """Return the output of 'openssl version'."""
    cmd = [get_openssl_executable(), "version"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return res.stdout.strip()


def get_python_openssl_version() -> str:
    """Return the underlying OpenSSL version compiled into PyCA Cryptography."""
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        return backend.openssl_version_text()
    except Exception as exc:
        return f"Unavailable ({exc})"


def inspect_rsa_key(pem_bytes: bytes, is_public: bool = False) -> Tuple[str, str]:
    """Run 'openssl rsa -text -noout' to inspect an RSA public or private key."""
    exe = get_openssl_executable()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
        f.write(pem_bytes)
        key_path = f.name

    try:
        cmd = [exe, "rsa", "-in", key_path, "-text", "-noout"]
        if is_public:
            cmd.insert(2, "-pubin")

        res = subprocess.run(cmd, capture_output=True, text=True)
        cmd_str = f"openssl rsa {'-pubin ' if is_public else ''}-in <key.pem> -text -noout"
        if res.returncode != 0:
            return cmd_str, f"Error (Exit {res.returncode}): {res.stderr.strip()}"
        return cmd_str, res.stdout.strip()
    finally:
        if os.path.exists(key_path):
            os.remove(key_path)


def openssl_digest(data_bytes: bytes, algo: str = "sha256") -> Tuple[str, str]:
    """Compute cryptographic hash using 'openssl dgst -<algo>'."""
    exe = get_openssl_executable()
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data_bytes)
        data_path = f.name

    try:
        cmd = [exe, "dgst", f"-{algo}", data_path]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        cmd_str = f"openssl dgst -{algo} <file>"
        output = res.stdout.strip()
        # Output is typically: SHA2-256(<path>)= <hash> or SHA256(<path>)= <hash>
        digest_hex = output.split("= ")[-1] if "= " in output else output
        return cmd_str, digest_hex
    finally:
        if os.path.exists(data_path):
            os.remove(data_path)


def openssl_sign(data_bytes: bytes, private_pem_bytes: bytes, algo: str = "sha256") -> Tuple[str, bytes]:
    """Sign data using 'openssl dgst -<algo> -sign <privkey>'."""
    exe = get_openssl_executable()
    with tempfile.NamedTemporaryFile(delete=False) as df, \
         tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        df.write(data_bytes)
        data_path = df.name
        kf.write(private_pem_bytes)
        key_path = kf.name

    try:
        cmd = [exe, "dgst", f"-{algo}", "-sign", key_path, data_path]
        res = subprocess.run(cmd, capture_output=True, check=True)
        cmd_str = f"openssl dgst -{algo} -sign <private_key.pem> -out <signature.bin> <file>"
        return cmd_str, res.stdout
    finally:
        if os.path.exists(data_path):
            os.remove(data_path)
        if os.path.exists(key_path):
            os.remove(key_path)


def openssl_verify(data_bytes: bytes, signature_bytes: bytes, public_pem_bytes: bytes, algo: str = "sha256") -> Tuple[str, bool, str]:
    """Verify signature using 'openssl dgst -<algo> -verify <pubkey> -signature <sig>'."""
    exe = get_openssl_executable()
    with tempfile.NamedTemporaryFile(delete=False) as df, \
         tempfile.NamedTemporaryFile(delete=False) as sf, \
         tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        df.write(data_bytes)
        data_path = df.name
        sf.write(signature_bytes)
        sig_path = sf.name
        kf.write(public_pem_bytes)
        key_path = kf.name

    try:
        cmd = [exe, "dgst", f"-{algo}", "-prverify" if False else "-verify", key_path, "-signature", sig_path, data_path]
        res = subprocess.run(cmd, capture_output=True, text=True)
        cmd_str = f"openssl dgst -{algo} -verify <public_key.pem> -signature <signature.bin> <file>"
        is_ok = (res.returncode == 0 and "OK" in res.stdout.upper())
        msg = res.stdout.strip() if res.stdout else res.stderr.strip()
        return cmd_str, is_ok, msg
    finally:
        for p in (data_path, sig_path, key_path):
            if os.path.exists(p):
                os.remove(p)


def openssl_symmetric_encrypt(plaintext: bytes, passphrase: str) -> Tuple[str, bytes]:
    """Encrypt using OpenSSL AES-256-CBC with PBKDF2 key derivation."""
    exe = get_openssl_executable()
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(plaintext)
        in_path = f.name

    try:
        cmd = [exe, "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-k", passphrase, "-in", in_path]
        res = subprocess.run(cmd, capture_output=True, check=True)
        cmd_str = "openssl enc -aes-256-cbc -pbkdf2 -salt -k <password> -in <plaintext> -out <ciphertext>"
        return cmd_str, res.stdout
    finally:
        if os.path.exists(in_path):
            os.remove(in_path)


def openssl_symmetric_decrypt(ciphertext: bytes, passphrase: str) -> Tuple[str, bytes]:
    """Decrypt using OpenSSL AES-256-CBC with PBKDF2 key derivation."""
    exe = get_openssl_executable()
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(ciphertext)
        in_path = f.name

    try:
        cmd = [exe, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-k", passphrase, "-in", in_path]
        res = subprocess.run(cmd, capture_output=True)
        cmd_str = "openssl enc -d -aes-256-cbc -pbkdf2 -k <password> -in <ciphertext> -out <plaintext>"
        if res.returncode != 0:
            raise ValueError(f"Decryption failed (bad password or corrupted data): {res.stderr.strip()}")
        return cmd_str, res.stdout
    finally:
        if os.path.exists(in_path):
            os.remove(in_path)

