"""FastAPI starter API. Local demo mode only; secure deployment requires auth/RBAC."""
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel
from crypto_utils import encrypt_file, decrypt_file, verify_package_signature

app = FastAPI(title="Enterprise Secure File Storage API", version="0.2.0")

class DecryptResult(BaseModel):
    filename: str
    content_base64: str
    signature_verified: bool

@app.get("/health")
def health():
    return {"status": "ok", "mode": "local-demo", "azure_integrated": False}

@app.post("/v1/files/encrypt")
async def encrypt_endpoint(
    file: UploadFile = File(...),
    recipient_public_key: UploadFile = File(...),
    sender_private_key: UploadFile = File(...),
):
    try:
        package = encrypt_file(file.filename or "upload.bin", await file.read(),
                               await recipient_public_key.read(), await sender_private_key.read())
        return {"filename": (file.filename or "upload.bin") + ".sfs",
                "package_base64": __import__('base64').b64encode(package).decode('ascii')}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Encryption failed: {type(exc).__name__}")

@app.post("/v1/files/verify")
async def verify_endpoint(package: UploadFile = File(...), sender_public_key: UploadFile = File(...)):
    try:
        valid = verify_package_signature(await package.read(), await sender_public_key.read())
        return {"signature_valid": valid}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Verification failed: {type(exc).__name__}")

@app.post("/v1/files/decrypt")
async def decrypt_endpoint(
    package: UploadFile = File(...), recipient_private_key: UploadFile = File(...),
    sender_public_key: UploadFile = File(...),
):
    try:
        filename, plaintext = decrypt_file(await package.read(), await recipient_private_key.read(),
                                           await sender_public_key.read())
        return {"filename": filename,
                "content_base64": __import__('base64').b64encode(plaintext).decode('ascii'),
                "signature_verified": True}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {type(exc).__name__}")
