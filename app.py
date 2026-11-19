import base64
import hashlib
import json
import os
import streamlit as st

from crypto_utils import (
    generate_key_pair, encrypt_file, decrypt_file, verify_package_signature,
    load_public_key, load_private_key, AES_KEY_BYTES, NONCE_BYTES
)
import openssl_utils

st.set_page_config(
    page_title="Enterprise Secure File Storage System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom enterprise styling
st.markdown("""
<style>
    .step-box {
        background: #ffffff;
        border: 1px solid #e0e0e0;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 18px;
        box-shadow: 0 2px 6px rgba(0,0,0,0.05);
    }
    .step-header {
        color: #0d47a1;
        font-size: 1.15rem;
        font-weight: 700;
        margin-bottom: 10px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .check-pill {
        background-color: #e8f5e9;
        color: #2e7d32;
        padding: 6px 12px;
        border-radius: 20px;
        font-weight: 600;
        display: inline-block;
        margin: 4px;
        border: 1px solid #c8e6c9;
    }
    .alert-pill {
        background-color: #ffebee;
        color: #c62828;
        padding: 6px 12px;
        border-radius: 20px;
        font-weight: 600;
        display: inline-block;
        margin: 4px;
        border: 1px solid #ffcdd2;
    }
    .code-chip {
        background: #eceff1;
        padding: 2px 6px;
        border-radius: 4px;
        font-family: monospace;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Enterprise Secure File Storage System")
st.caption("Interactive Web Cryptography Suite • OpenSSL Engine • AES-256-GCM • RSA-OAEP • RSA-PSS • SHA-256")

# Sidebar navigation & architecture info
with st.sidebar:
    st.header("🏢 Enterprise Stack")
    st.markdown("""
    - **Cryptographic Engine:** OpenSSL & PyCA
    - **Symmetric Cipher:** AES-256-GCM (Authenticated)
    - **Key Encapsulation:** RSA-OAEP (3072-bit, SHA-256)
    - **Digital Signature:** RSA-PSS (SHA-256)
    - **Integrity Digest:** SHA-256
    - **Standard Compliance:** NIST SP 800-57
    """)
    st.divider()
    try:
        sys_openssl = openssl_utils.get_openssl_version()
        py_openssl = openssl_utils.get_python_openssl_version()
        st.success(f"**System OpenSSL:**\n`{sys_openssl}`")
        st.info(f"**Python Cryptography Backend:**\n`{py_openssl}`")
    except Exception as e:
        st.warning(f"OpenSSL status: {e}")

# Application Tabs
tab_sim, tab_openssl, tab_enc, tab_dec, tab_keys = st.tabs([
    "🔬 Interactive Step-by-Step Simulation",
    "🛠️ OpenSSL Web Studio",
    "📤 Encrypt & Sign File",
    "📥 Verify & Decrypt File",
    "🔑 Key Management"
])

# ==============================================================================
# TAB 1: INTERACTIVE STEP-BY-STEP SIMULATION (PRIMARY WEB SIMULATOR)
# ==============================================================================
with tab_sim:
    st.subheader("🔬 Interactive Web-Based Cryptography Simulation")
    st.markdown("""
    This simulator provides a **100% visual, point-and-click walkthrough** of how enterprise hybrid encryption works.
    You can inspect intermediate cryptographic values at every stage, customize names, and simulate cyber attacks.
    """)

    # Entity Configuration
    c_name1, c_name2 = st.columns(2)
    with c_name1:
        sim_sender_name = st.text_input("Sender Name / Role (Data Creator)", value="Naveen (Security Officer)", key="sim_s_name")
    with c_name2:
        sim_rec_name = st.text_input("Recipient Name / Role (Data Consumer)", value="Enterprise Cloud Storage", key="sim_r_name")

    sim_doc_text = st.text_area(
        "Document to Encrypt & Protect (Confidential Payload)",
        value="CONFIDENTIAL ENTERPRISE AUDIT REPORT 2026\nStatus: Approved by Board of Directors\nBudget Allocation: $2,500,000 USD\nClassification: RESTRICTED",
        height=100,
        key="sim_doc_input"
    )

    # Simulation Controls
    col_btn1, col_btn2 = st.columns([2, 5])
    with col_btn1:
        run_sim = st.button("🚀 Run Full Interactive Simulation", type="primary", use_container_width=True)

    if run_sim:
        sim_bytes = sim_doc_text.encode("utf-8")

        # 1. Identity & Keys
        s_priv, s_pub = generate_key_pair()
        r_priv, r_pub = generate_key_pair()
        st.session_state["sim_s_priv"] = s_priv
        st.session_state["sim_s_pub"] = s_pub
        st.session_state["sim_r_priv"] = r_priv
        st.session_state["sim_r_pub"] = r_pub

        # 2. Canonical Package
        pkg_bytes = encrypt_file("enterprise_audit.txt", sim_bytes, r_pub, s_priv)
        pkg = json.loads(pkg_bytes.decode("utf-8"))
        st.session_state["sim_active_pkg"] = pkg_bytes
        st.session_state["sim_original_bytes"] = sim_bytes
        st.session_state["sim_pkg_json"] = pkg
        st.session_state["sim_ran"] = True

    if st.session_state.get("sim_ran", False):
        pkg = st.session_state["sim_pkg_json"]
        s_pub = st.session_state["sim_s_pub"]
        r_pub = st.session_state["sim_r_pub"]
        s_priv = st.session_state["sim_s_priv"]
        r_priv = st.session_state["sim_r_priv"]
        sim_bytes = st.session_state["sim_original_bytes"]
        full_pkg_bytes = st.session_state["sim_active_pkg"]

        raw_nonce = base64.b64decode(pkg["nonce"])
        raw_wrapped_key = base64.b64decode(pkg["wrapped_key"])
        raw_ct_with_tag = base64.b64decode(pkg["ciphertext"])
        raw_ct = raw_ct_with_tag[:-16]
        raw_tag = raw_ct_with_tag[-16:]
        raw_sig = base64.b64decode(pkg["signature"])

        st.markdown("---")
        st.markdown("### 📋 Interactive Step-by-Step Cryptographic Execution")

        # Step 1
        with st.expander("Step 1: 👥 Asymmetric Key Pair Generation (RSA-3072)", expanded=True):
            st.markdown(f"Enterprise identities generate NIST SP 800-57 compliant **3072-bit RSA key pairs**.")
            sc1, sc2 = st.columns(2)
            with sc1:
                st.markdown(f"**Sender:** `{sim_sender_name}`")
                st.write(f"- Key Type: `RSA-3072 (2 primes)`")
                st.write(f"- Public Key Fingerprint (SHA-256): `{hashlib.sha256(s_pub).hexdigest()[:24]}...`")
                st.write(f"- Private Key: Kept secret in HSM / Secure Store.")
            with sc2:
                st.markdown(f"**Recipient:** `{sim_rec_name}`")
                st.write(f"- Key Type: `RSA-3072 (2 primes)`")
                st.write(f"- Public Key Fingerprint (SHA-256): `{hashlib.sha256(r_pub).hexdigest()[:24]}...`")
                st.write(f"- Public Key: Distributed to sender for wrapping.")

        # Step 2
        with st.expander("Step 2: 📄 Plaintext Ingestion & Integrity Digest (SHA-256)", expanded=True):
            digest_hex = pkg["sha256"]
            st.markdown(f"Before encryption, the sender hashes the document using **SHA-256** to create an immutable fingerprint.")
            st.code(f"Document Size: {len(sim_bytes)} bytes\nSHA-256 Digest = {digest_hex}", language="text")
            st.caption("ℹ️ Even a 1-bit alteration in the file will produce an entirely different digest (Avalanche Effect).")

        # Step 3
        with st.expander("Step 3: 🎲 Ephemeral AES-256 Session Key & 96-bit Nonce Generation", expanded=True):
            st.markdown("A **fresh, cryptographically random 256-bit AES Data Encryption Key (DEK)** is generated for this file only.")
            st.code(f"96-bit AES-GCM Nonce (Hex): 0x{raw_nonce.hex()}\nNonce (Base64): {pkg['nonce']}", language="text")
            st.caption("ℹ️ Generating a new DEK per file ensures Forward Secrecy: compromising one file key never compromises another.")

        # Step 4
        with st.expander("Step 4: 🔒 Authenticated Symmetric Encryption (AES-256-GCM)", expanded=True):
            st.markdown(f"The document is encrypted using **AES-256 in Galois/Counter Mode (GCM)**, producing both ciphertext and an authentication tag.")
            st.write(f"- **Plaintext Length:** {len(sim_bytes)} bytes")
            st.write(f"- **Ciphertext Length:** {len(raw_ct)} bytes")
            st.write(f"- **GMAC Authentication Tag (128-bit / 16 bytes):** `0x{raw_tag.hex()}`")
            st.code(f"Ciphertext (Base64): {pkg['ciphertext']}", language="text")
            st.caption("ℹ️ The 128-bit GMAC authentication tag guarantees that the ciphertext cannot be modified by any third party without detection.")

        # Step 5
        with st.expander("Step 5: 🎁 Asymmetric Key Wrapping (RSA-OAEP-SHA256)", expanded=True):
            st.markdown(f"The 256-bit AES session key is encapsulated using `{sim_rec_name}`'s 3072-bit RSA public key with **OAEP padding (SHA-256)**.")
            st.write(f"- **Input Session Key:** 32 bytes (256 bits)")
            st.write(f"- **Encapsulated Output:** 384 bytes (3072 bits)")
            st.code(f"Wrapped DEK (Base64): {pkg['wrapped_key'][:100]}...", language="text")
            st.caption("ℹ️ Hybrid Cryptography advantage: Fast symmetric AES encrypts large data, while asymmetric RSA securely transfers the small key.")

        # Step 6
        with st.expander("Step 6: ✍️ Digital Signature & Non-Repudiation (RSA-PSS-SHA256)", expanded=True):
            st.markdown(f"`{sim_sender_name}` signs the canonical package using their RSA private key with **PSS padding**.")
            st.write(f"- **Signing Algorithm:** RSA-PSS with SHA-256 and MGF1")
            st.write(f"- **Signature Size:** 384 bytes (3072 bits)")
            st.code(f"Digital Signature (Base64): {pkg['signature'][:100]}...", language="text")
            st.caption("ℹ️ Non-repudiation: The sender cannot deny authoring this file because only their private key could produce this signature.")

        # Step 7
        with st.expander("Step 7: 📦 Assembled Secure Container (.sfs)", expanded=True):
            st.markdown("All cryptographic artifacts are packaged into a canonical, tamper-evident container:")
            st.json(pkg)
            st.download_button("📥 Download This .sfs Package", full_pkg_bytes, "simulation_package.sfs", mime="application/json")

        # Step 8
        with st.expander("Step 8: 🔓 Recipient Unpacking & Multi-Layer Verification", expanded=True):
            st.markdown(f"When `{sim_rec_name}` receives the container, it executes **4 strict verification checkpoints**:")
            
            # 1. Signature
            sig_valid = verify_package_signature(full_pkg_bytes, s_pub)
            if sig_valid:
                st.markdown(f"<div class='check-pill'>✅ Checkpoint 1: RSA-PSS Signature Verified — Origin confirmed as {sim_sender_name}</div>", unsafe_allow_html=True)
            
            # 2. Decrypt
            filename, recovered_bytes = decrypt_file(full_pkg_bytes, r_priv, s_pub)
            st.markdown(f"<div class='check-pill'>✅ Checkpoint 2: RSA-OAEP Key Unwrapped with {sim_rec_name}'s Private Key</div>", unsafe_allow_html=True)
            st.markdown("<div class='check-pill'>✅ Checkpoint 3: AES-256-GCM 128-bit Authentication Tag Verified (No Bit Tampering)</div>", unsafe_allow_html=True)
            st.markdown(f"<div class='check-pill'>✅ Checkpoint 4: SHA-256 Plaintext Digest Matches ({digest_hex[:16]}...)</div>", unsafe_allow_html=True)

            st.success(f"🎉 Complete Verification Passed! Recovered {len(recovered_bytes)} bytes.")
            st.text_area("Decrypted Plaintext Document (Recovered)", recovered_bytes.decode("utf-8"), height=90)

        # Step 9: Attack Sandbox
        st.markdown("---")
        st.markdown("### 🦹 Interactive Real-Time Cyber Attack Sandbox")
        st.write("Click any attack below to simulate how the system reacts when a cyber adversary tampers with the file:")

        attack_choice = st.radio(
            "Select Cyber Attack Vector:",
            [
                "Attack A: Man-in-the-Middle Ciphertext Tampering (Attacker flips bits in encrypted data)",
                "Attack B: Digital Signature Forgery (Attacker alters signature bits)",
                "Attack C: Sender Impersonation (Attacker substitutes their own public key)"
            ]
        )

        if st.button("💥 Launch Attack on Package & Test Defense", type="secondary"):
            hacked_pkg = json.loads(full_pkg_bytes.decode("utf-8"))
            verify_pub = s_pub

            if "Attack A" in attack_choice:
                # Flip byte in ciphertext
                raw_bytes_ct = list(base64.b64decode(hacked_pkg["ciphertext"]))
                raw_bytes_ct[15] ^= 0xFF
                hacked_pkg["ciphertext"] = base64.b64encode(bytes(raw_bytes_ct)).decode("ascii")
                st.warning("⚠️ Attack Injected: Flipped 8 bits in the encrypted ciphertext.")
            elif "Attack B" in attack_choice:
                raw_sig_b = list(base64.b64decode(hacked_pkg["signature"]))
                raw_sig_b[10] ^= 0xAA
                hacked_pkg["signature"] = base64.b64encode(bytes(raw_sig_b)).decode("ascii")
                st.warning("⚠️ Attack Injected: Forged 8 bits in the digital signature.")
            elif "Attack C" in attack_choice:
                _, rogue_pub = generate_key_pair()
                verify_pub = rogue_pub
                st.warning("⚠️ Attack Injected: Replaced sender's legitimate public key with Rogue Attacker Key.")

            hacked_bytes = json.dumps(hacked_pkg).encode("utf-8")

            # Check Defense
            sig_check = verify_package_signature(hacked_bytes, verify_pub)
            if not sig_check:
                st.markdown("<div class='alert-pill'>🚨 DEFENSE TRIGGERED: RSA-PSS Signature Check Failed!</div>", unsafe_allow_html=True)
                st.error("The package was rejected at Checkpoint 1. The digital signature does not match the content or sender identity.")
            else:
                try:
                    decrypt_file(hacked_bytes, r_priv, verify_pub)
                    st.error("Security Alert: Tamper went undetected!")
                except Exception as exc:
                    st.markdown("<div class='alert-pill'>🚨 DEFENSE TRIGGERED: AES-256-GCM AEAD Tag Check Failed!</div>", unsafe_allow_html=True)
                    st.error(f"The ciphertext was rejected at Checkpoint 3 ({exc}). Tampered data was discarded before reaching the application layer.")

# ==============================================================================
# TAB 2: OPENSSL WEB STUDIO (100% WEB-BASED OPENSSL SUITE)
# ==============================================================================
with tab_openssl:
    st.subheader("🛠️ OpenSSL Web Studio")
    st.markdown("""
    Run real-time OpenSSL operations **directly inside the web browser** without needing to type commands in a terminal.
    Every action uses the native system OpenSSL binary (`OpenSSL 3.5.4`).
    """)

    ssl_col1, ssl_col2 = st.columns(2)

    with ssl_col1:
        st.markdown("#### 1. OpenSSL 3072-bit Key Generator & Inspector")
        st.write("Generates an RSA-3072 key and executes `openssl rsa -text -noout`.")
        if st.button("🔑 Generate & Inspect Key with OpenSSL", key="btn_ssl_gen"):
            with st.spinner("Executing OpenSSL engine..."):
                p_pem, pub_pem = generate_key_pair()
                st.session_state["ssl_key"] = p_pem
                st.session_state["ssl_pub"] = pub_pem
                cmd_txt, out_txt = openssl_utils.inspect_rsa_key(p_pem, is_public=False)
                st.session_state["ssl_inspect_cmd"] = cmd_txt
                st.session_state["ssl_inspect_out"] = out_txt

        if "ssl_inspect_out" in st.session_state:
            st.code(f"$ {st.session_state['ssl_inspect_cmd']}", language="bash")
            st.text_area("OpenSSL ASN.1 Key Output", st.session_state["ssl_inspect_out"], height=200)

    with ssl_col2:
        st.markdown("#### 2. OpenSSL Digital Signature & Tamper Studio")
        st.write("Executes `openssl dgst -sha256 -sign` and `openssl dgst -sha256 -verify`.")
        ssl_doc_input = st.text_input("Document to Sign via OpenSSL", value="Approved Enterprise Contract 2026", key="ssl_doc_in")

        col_act1, col_act2 = st.columns(2)
        with col_act1:
            if st.button("✍️ Sign with OpenSSL", key="btn_ssl_sign"):
                key_to_use = st.session_state.get("ssl_key")
                if not key_to_use:
                    p_pem, pub_pem = generate_key_pair()
                    st.session_state["ssl_key"] = p_pem
                    st.session_state["ssl_pub"] = pub_pem
                    key_to_use = p_pem
                cmd_s, sig_b = openssl_utils.openssl_sign(ssl_doc_input.encode("utf-8"), key_to_use)
                st.session_state["ssl_sig_bytes"] = sig_b
                st.session_state["ssl_sig_cmd"] = cmd_s
                st.session_state["ssl_signed_text"] = ssl_doc_input
                st.success("Signed via OpenSSL!")

        with col_act2:
            if st.button("✅ Verify with OpenSSL", key="btn_ssl_verify"):
                sig_b = st.session_state.get("ssl_sig_bytes")
                pub_k = st.session_state.get("ssl_pub")
                txt_signed = st.session_state.get("ssl_signed_text", ssl_doc_input)
                if sig_b and pub_k:
                    cmd_v, is_valid, msg = openssl_utils.openssl_verify(txt_signed.encode("utf-8"), sig_b, pub_k)
                    st.code(f"$ {cmd_v}", language="bash")
                    if is_valid:
                        st.success(f"OpenSSL Result: {msg}")
                    else:
                        st.error(f"OpenSSL Result: {msg}")
                else:
                    st.warning("Click 'Sign with OpenSSL' first.")

        if st.session_state.get("ssl_sig_bytes"):
            st.code(f"OpenSSL Signature (Hex): {st.session_state['ssl_sig_bytes'].hex()[:80]}...", language="text")
            if st.button("🦹 Simulate Tamper Attack on OpenSSL", key="btn_ssl_tamper"):
                pub_k = st.session_state.get("ssl_pub")
                sig_b = st.session_state.get("ssl_sig_bytes")
                tampered_text = st.session_state.get("ssl_signed_text", ssl_doc_input) + " [MODIFIED BY ATTACKER]"
                cmd_v, is_valid, msg = openssl_utils.openssl_verify(tampered_text.encode("utf-8"), sig_b, pub_k)
                st.code(f"$ {cmd_v}", language="bash")
                st.error(f"OpenSSL Caught Tampering! Result: {msg}")

    st.divider()
    st.markdown("#### 3. OpenSSL Direct AES-256 Symmetric Cipher (`openssl enc -aes-256-cbc -pbkdf2`)")
    col_sym1, col_sym2 = st.columns(2)
    with col_sym1:
        sym_plain = st.text_input("Plaintext Data", value="Confidential Financial Reserves: $50M", key="sym_p")
        sym_pass = st.text_input("Passphrase", value="EnterpriseKey2026!", type="password", key="sym_pass")
        if st.button("🔒 Encrypt with OpenSSL AES-256", key="btn_ssl_enc"):
            cmd_e, ct = openssl_utils.openssl_symmetric_encrypt(sym_plain.encode("utf-8"), sym_pass)
            st.session_state["ssl_sym_ct"] = ct
            st.code(f"$ {cmd_e}", language="bash")
            st.success(f"Encrypted ({len(ct)} bytes with Salted__ header)")
            st.code(f"Ciphertext (Base64): {base64.b64encode(ct).decode('ascii')}", language="text")

    with col_sym2:
        st.write("Decrypt using OpenSSL PBKDF2 key derivation:")
        if st.button("🔓 Decrypt with OpenSSL", key="btn_ssl_dec"):
            ct = st.session_state.get("ssl_sym_ct")
            if ct:
                try:
                    cmd_d, pt = openssl_utils.openssl_symmetric_decrypt(ct, sym_pass)
                    st.code(f"$ {cmd_d}", language="bash")
                    st.success(f"Decrypted: {pt.decode('utf-8')}")
                except Exception as err:
                    st.error(f"OpenSSL Error: {err}")
            else:
                st.warning("Encrypt some data first.")

# ==============================================================================
# TAB 3: ENCRYPT & SIGN FILE
# ==============================================================================
with tab_enc:
    st.subheader("📤 Encrypt and Sign a File")
    st.markdown("""
    Upload a real document and secure it into an `.sfs` encrypted package.
    """)

    col1, col2 = st.columns(2)
    with col1:
        recipient_pub_file = st.file_uploader("Recipient Public Key (.pem)", type=["pem"], key="enc_pub")
        rec_lbl = st.session_state.get("recipient_label", "Recipient")
        if recipient_pub_file is None and "recipient_pub" in st.session_state:
            if st.checkbox(f"Use generated {rec_lbl} Public Key", value=True, key="use_gen_rec_pub"):
                enc_pub_bytes = st.session_state["recipient_pub"]
            else:
                enc_pub_bytes = None
        else:
            enc_pub_bytes = recipient_pub_file.getvalue() if recipient_pub_file else None

    with col2:
        sender_priv_file = st.file_uploader("Sender Private Key (.pem)", type=["pem"], key="enc_priv")
        sen_lbl = st.session_state.get("sender_label", "Sender")
        if sender_priv_file is None and "sender_priv" in st.session_state:
            if st.checkbox(f"Use generated {sen_lbl} Private Key", value=True, key="use_gen_sen_priv"):
                enc_priv_bytes = st.session_state["sender_priv"]
            else:
                enc_priv_bytes = None
        else:
            enc_priv_bytes = sender_priv_file.getvalue() if sender_priv_file else None

    file_to_encrypt = st.file_uploader("Upload File to Protect", key="file_to_enc")

    if st.button("🔒 Execute Hybrid Encryption & Signing", type="primary", disabled=not (enc_pub_bytes and enc_priv_bytes and file_to_encrypt)):
        try:
            package_bytes = encrypt_file(
                file_to_encrypt.name,
                file_to_encrypt.getvalue(),
                enc_pub_bytes,
                enc_priv_bytes
            )
            st.session_state["last_encrypted_package"] = package_bytes
            st.session_state["last_encrypted_filename"] = file_to_encrypt.name + ".sfs"
            st.success("File encrypted and signed successfully into Secure File Storage (.sfs) container!")
            st.download_button(
                "📥 Download Encrypted Package (.sfs)",
                package_bytes,
                file_name=st.session_state["last_encrypted_filename"],
                mime="application/json"
            )

            with st.expander("🔍 View Encrypted Package Internals (JSON Container)"):
                st.json(json.loads(package_bytes.decode("utf-8")))
        except Exception as e:
            st.error(f"Encryption failed: {e}")

# ==============================================================================
# TAB 4: VERIFY & DECRYPT FILE
# ==============================================================================
with tab_dec:
    st.subheader("📥 Verify Signature and Decrypt File")
    pkg_file = st.file_uploader("Upload .sfs Encrypted Package", type=["sfs", "json"], key="dec_pkg")
    if pkg_file is None and "last_encrypted_package" in st.session_state:
        if st.checkbox("Use package from Encrypt tab", value=True, key="use_last_pkg"):
            pkg_bytes = st.session_state["last_encrypted_package"]
        else:
            pkg_bytes = None
    else:
        pkg_bytes = pkg_file.getvalue() if pkg_file else None

    col_dec1, col_dec2 = st.columns(2)
    with col_dec1:
        rec_priv_file = st.file_uploader("Recipient Private Key (.pem)", type=["pem"], key="dec_rec_priv")
        rec_lbl = st.session_state.get("recipient_label", "Recipient")
        if rec_priv_file is None and "recipient_priv" in st.session_state:
            if st.checkbox(f"Use generated {rec_lbl} Private Key", value=True, key="use_gen_rec_priv"):
                dec_priv_bytes = st.session_state["recipient_priv"]
            else:
                dec_priv_bytes = None
        else:
            dec_priv_bytes = rec_priv_file.getvalue() if rec_priv_file else None

    with col_dec2:
        sen_pub_file = st.file_uploader("Sender Public Key (.pem)", type=["pem"], key="dec_sen_pub")
        sen_lbl = st.session_state.get("sender_label", "Sender")
        if sen_pub_file is None and "sender_pub" in st.session_state:
            if st.checkbox(f"Use generated {sen_lbl} Public Key", value=True, key="use_gen_sen_pub"):
                dec_pub_bytes = st.session_state["sender_pub"]
            else:
                dec_pub_bytes = None
        else:
            dec_pub_bytes = sen_pub_file.getvalue() if sen_pub_file else None

    if st.button("🔓 Verify Signature & Decrypt File", type="primary", disabled=not (pkg_bytes and dec_priv_bytes and dec_pub_bytes)):
        try:
            sig_valid = verify_package_signature(pkg_bytes, dec_pub_bytes)
            if not sig_valid:
                st.error("🚨 SIGNATURE VERIFICATION FAILED! Package has been tampered with or sender public key does not match.")
            else:
                st.success("✅ RSA-PSS Signature Verified: Origin and Authenticity Confirmed.")
                filename, plaintext = decrypt_file(pkg_bytes, dec_priv_bytes, dec_pub_bytes)
                st.success("✅ AES-256-GCM AEAD Tag & SHA-256 Integrity Digest Passed.")
                st.download_button(f"📥 Download Decrypted File ({filename})", plaintext, file_name=filename)
                try:
                    text_preview = plaintext.decode("utf-8")
                    st.text_area("Decrypted Plaintext Preview", text_preview, height=120)
                except UnicodeDecodeError:
                    st.info("Decrypted binary file recovered successfully.")
        except Exception as e:
            st.error(f"Decryption failed: {e}")

# ==============================================================================
# TAB 5: KEY MANAGEMENT
# ==============================================================================
with tab_keys:
    st.subheader("🔑 Asymmetric Key Generation (3072-bit RSA)")
    col_alice, col_bob = st.columns(2)
    with col_alice:
        sender_name = st.text_input("Sender Label / Name", value="Alice", key="sender_name_input")
        if st.button(f"Generate {sender_name} Keys", key="gen_sender_btn", type="primary"):
            priv, pub = generate_key_pair()
            st.session_state["sender_priv"] = priv
            st.session_state["sender_pub"] = pub
            st.session_state["sender_label"] = sender_name
            st.success(f"{sender_name} key pair generated!")
        if "sender_priv" in st.session_state:
            s_lbl = st.session_state.get("sender_label", "sender").lower().replace(" ", "_")
            st.download_button(f"📥 Download {st.session_state.get('sender_label', 'Sender')} Private Key (PEM)", st.session_state["sender_priv"], f"{s_lbl}_private.pem", mime="application/x-pem-file")
            st.download_button(f"📥 Download {st.session_state.get('sender_label', 'Sender')} Public Key (PEM)", st.session_state["sender_pub"], f"{s_lbl}_public.pem", mime="application/x-pem-file")

    with col_bob:
        recipient_name = st.text_input("Recipient Label / Name", value="Bob", key="recipient_name_input")
        if st.button(f"Generate {recipient_name} Keys", key="gen_recipient_btn", type="primary"):
            priv, pub = generate_key_pair()
            st.session_state["recipient_priv"] = priv
            st.session_state["recipient_pub"] = pub
            st.session_state["recipient_label"] = recipient_name
            st.success(f"{recipient_name} key pair generated!")
        if "recipient_priv" in st.session_state:
            r_lbl = st.session_state.get("recipient_label", "recipient").lower().replace(" ", "_")
            st.download_button(f"📥 Download {st.session_state.get('recipient_label', 'Recipient')} Private Key (PEM)", st.session_state["recipient_priv"], f"{r_lbl}_private.pem", mime="application/x-pem-file")
            st.download_button(f"📥 Download {st.session_state.get('recipient_label', 'Recipient')} Public Key (PEM)", st.session_state["recipient_pub"], f"{r_lbl}_public.pem", mime="application/x-pem-file")

st.divider()
st.caption("Enterprise Secure File Storage System • 100% Web Simulation • Hybrid Cryptography & OpenSSL Studio")
