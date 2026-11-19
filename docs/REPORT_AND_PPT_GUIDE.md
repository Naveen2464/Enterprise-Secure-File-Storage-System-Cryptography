# Report and PPT content guide

## Abstract
The Enterprise Secure File Storage System demonstrates hybrid cryptography and OpenSSL integration for protecting enterprise files. Each file is encrypted using a fresh AES-256-GCM data key. RSA-OAEP-SHA256 protects the data key, SHA-256 provides a digest, and RSA-PSS-SHA256 signs the package. The application provides key generation, encryption, signature verification, decryption, a complete interactive attack simulation sandbox, and a native OpenSSL CLI engine through Streamlit. FastAPI and optional Azure Key Vault/Blob adapter starter code are included. Azure Key Vault, Blob Storage, Entra ID, PostgreSQL operations and Azure Monitor integration form the cloud deployment architecture.

## Problem statement
Files stored or transferred across enterprise networks without strong cryptographic controls risk unauthorized disclosure, tampering, and repudiation. This project demonstrates confidentiality, integrity, authenticity, and non-repudiation using industry-standard OpenSSL and PyCA hybrid cryptography, complemented by an interactive attack simulation sandbox and enterprise cloud architecture.

## Objectives
- Encrypt files using AES-256-GCM authenticated encryption.
- Protect each file's ephemeral AES key using RSA-OAEP-SHA256.
- Provide non-repudiation and verify package signatures using RSA-PSS-SHA256.
- Calculate SHA-256 digests and detect integrity failures.
- Provide native OpenSSL CLI execution (key inspection, hashing, signing, and symmetric encryption).
- Provide an interactive simulation sandbox with real-time cyber attack and tamper testing.
- Design a cloud-ready architecture using Microsoft Azure (Key Vault, Blob Storage, Entra ID).

## Suggested PPT (10–12 slides)
1. Title and team members
2. Introduction and problem statement
3. Objectives and scope
4. Existing vs proposed system
5. Architecture diagram
6. Hybrid cryptography workflow
7. Algorithms: AES-GCM, RSA-OAEP, SHA-256, RSA-PSS
8. Modules and technology stack
9. Implementation screenshots / local demo
10. Testing and results (only actual test outcomes)
11. Azure roadmap, limitations and future scope
12. Conclusion and references

## Five-line description for Viva / Presentation
1. Our project is an Enterprise Secure File Storage System implementing hybrid cryptography with OpenSSL and PyCA engines.
2. AES-256-GCM encrypts file contents, while RSA-OAEP wraps the ephemeral encryption key.
3. SHA-256 enforces integrity checking, and RSA-PSS provides digital signatures for non-repudiation.
4. Native OpenSSL CLI tools and an interactive tamper attack simulation demonstrate real-time defense against data corruption and signature forgery.
5. The cloud architecture incorporates Azure Key Vault (HSM), Blob Storage, Entra ID, and PostgreSQL for enterprise scalability.
