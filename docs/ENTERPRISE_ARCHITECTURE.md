# Enterprise Architecture and Implementation Status

## Project title
Enterprise Secure File Storage System Using Hybrid Cryptography and Microsoft Azure

## Architecture (target design)
- **Frontend:** Streamlit initially; can be replaced or expanded later without changing the cryptographic format.
- **Backend:** FastAPI REST API.
- **Cryptography:** PyCA Cryptography; AES-256-GCM per-file data encryption, RSA-OAEP-SHA256 data-key wrapping, SHA-256 digest, RSA-PSS-SHA256 package signature.
- **Key management:** Azure Key Vault RSA key operations and key version lifecycle (target integration).
- **Identity:** Microsoft Entra ID authentication/MFA (target integration); application RBAC checks authorization.
- **Object storage:** Azure Blob Storage for encrypted packages only (target integration).
- **Metadata:** PostgreSQL for owner, filename, permissions, blob reference, digest and key version (starter model included).
- **Monitoring:** Azure Monitor plus structured audit events (starter logger included).
- **Deployment:** Windows local development first; hybrid local app/backend connected to Azure services after subscription and configuration; App Service is a later deployment option.

## File encryption workflow
1. Authenticate user with Entra ID and authorize the requested action (not yet wired into the demo API).
2. Generate a unique random 256-bit AES data-encryption key (DEK) per file.
3. Encrypt file bytes with AES-256-GCM and bind filename/version as authenticated metadata.
4. Wrap the DEK using RSA-OAEP-SHA256 (local demo uses recipient RSA public PEM; target cloud design uses Key Vault).
5. Sign the canonical package with RSA-PSS-SHA256 (local demo uses sender private PEM; target cloud design uses a signing key in Key Vault).
6. Store only the encrypted package in Blob Storage; save metadata and permissions in PostgreSQL.
7. On retrieval, authorize, verify signature, unwrap the DEK, decrypt with AES-GCM, and validate digest.

## Current implementation status

| Capability | Status in this ZIP |
|---|---|
| Streamlit key generation, encrypt, verify and decrypt | Implemented locally |
| AES-256-GCM, RSA-OAEP-SHA256, SHA-256, RSA-PSS-SHA256 | Implemented locally |
| Unit tests for crypto workflow | Included; run locally |
| FastAPI starter endpoints | Implemented in local-demo mode; PEM keys supplied per request |
| Azure Key Vault adapter | Starter adapter included; requires Azure resources and permissions |
| Azure Blob Storage adapter | Starter adapter included; requires Azure resources and permissions |
| PostgreSQL metadata model | Starter model included; migrations/session/API integration remain to do |
| Entra ID authentication and app RBAC | Planned; not implemented/enforced in this demo |
| Azure Monitor integration | Planned; audit logger starter included |
| Azure deployment | Not completed |

Do not present planned services as completed integration in a report or viva.

## Security limitations and production checklist
- The local demo exports unencrypted private PEM files. Do not use real confidential files or commit PEMs.
- The FastAPI demo endpoints accept private-key files in requests and have no authentication or authorization. Keep the API bound to localhost; do not expose it to a network.
- The API currently returns decrypted content as Base64 JSON for demonstration; a production API should stream a response and enforce size limits.
- Add Entra ID JWT validation, RBAC/ownership checks, rate limits, upload size limits, secure secret handling, database migrations, malware scanning, backup/restore, key rotation, alerting, and independent security review before production.
- Configure Key Vault soft delete and purge protection, least-privilege RBAC, managed identity, diagnostics/audit logging, and key rotation policies.
- Blob Storage service-side encryption is separate from application-level encryption. This design stores application ciphertext in Blob Storage.

## Windows setup

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Run API separately in another terminal:

```powershell
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs` for local API docs. The Streamlit UI remains the primary demo. API endpoints are not yet connected to the UI.

## Azure setup outline (when an Azure account is available)
1. Create a resource group, Key Vault, Storage Account and private Blob container.
2. Enable managed identity for the deployed backend (or use `az login` locally for development).
3. Grant only required Key Vault crypto permissions and Blob data permissions to the backend identity.
4. Set `AZURE_KEY_VAULT_URL` and `AZURE_STORAGE_ACCOUNT_URL`; configure diagnostics to Azure Monitor.
5. Configure Entra app registration and implement/validate JWTs and application RBAC before exposing endpoints.
6. Configure PostgreSQL, migrations, backups, private networking and monitoring.

## Four-member work allocation
1. **Cryptography & Key Management:** AES-GCM, RSA-OAEP, RSA-PSS, Key Vault wrapping/signing, key versioning and rotation.
2. **Backend & Database:** FastAPI services, Blob Storage, PostgreSQL schema/migrations, upload/download metadata APIs.
3. **Authentication & Access Control:** Entra ID, MFA, JWT validation, roles (admin/sender/recipient), ownership and authorization tests.
4. **Frontend, Monitoring & Testing:** Streamlit integration, audit events/Azure Monitor, integration/security tests, documentation and demo.

## Suggested six phases
1. Baseline and verify the existing local cryptography app.
2. Provision Azure resources and managed identity permissions.
3. Implement backend services and Key Vault/Blob adapters.
4. Implement Entra ID authentication and RBAC.
5. Integrate PostgreSQL metadata, audit logging, monitoring and key rotation.
6. Perform security/integration tests and deploy after review.
