# 🔐 File Encryption & Decryption Tool

A simple, secure desktop application for encrypting and decrypting files using **AES-256-CBC**, built with Python and Tkinter.

---

## Overview

This tool lets you protect any file on your system with a password. It uses industry-standard cryptography — AES-256 in CBC mode, with keys derived from your password via PBKDF2-HMAC-SHA256 (600,000 iterations) — so your files stay secure even if someone gets hold of the encrypted version.

No internet connection, no third-party servers, no accounts. Everything runs locally on your machine.

---

## Features

- **AES-256-CBC encryption** — one of the most trusted symmetric encryption algorithms available
- **PBKDF2-HMAC-SHA256 key derivation** (600,000 iterations) — makes brute-force password attacks computationally expensive
- **Random salt & IV per encryption** — encrypting the same file twice with the same password never produces identical output
- **Simple Tkinter GUI** — file picker, password field with show/hide toggle, and clear status feedback
- **Works with any file type** — text, images, documents, binaries, etc.
- **Fully offline** — no cloud dependency, no data leaves your machine

---

## How It Works

**Encryption:**
1. Pick a file
2. Enter a password
3. A random salt and IV are generated
4. Your password + salt → 256-bit AES key (via PBKDF2)
5. File is encrypted and saved as `<filename>.enc`

**Decryption:**
1. Pick the `.enc` file
2. Enter the same password used to encrypt it
3. Salt and IV are extracted from the file
4. The original file is restored

```
Encrypted file layout:
[ Salt (16 bytes) ][ IV (16 bytes) ][ Ciphertext ]
```

---

## Installation

```bash
git clone https://github.com/devShivam49/Encryption-Decryption.git
cd Encryption-Decryption
pip install -r requirements.txt
python main.py
```

**Requirements:**
- Python 3.7+
- [pycryptodome](https://pypi.org/project/pycryptodome/) (installed via `requirements.txt`)

---

## Tech Stack

| Component         | Technology                        |
|-------------------|------------------------------------|
| Language           | Python 3                          |
| GUI                | Tkinter                           |
| Cryptography       | PyCryptodome (AES-256-CBC)        |
| Key Derivation      | hashlib (PBKDF2-HMAC-SHA256)      |

---

## Security Notes

- Passwords are never stored — only used to derive the encryption key at runtime
- Each encryption uses a freshly generated random salt and IV
- This project uses CBC mode, which provides confidentiality but not built-in integrity verification (no tamper-detection). A future version may move to AES-GCM for authenticated encryption.

---

## Limitations

- Single file at a time (no batch/folder encryption yet)
- Entire file is loaded into memory (large files limited by available RAM)
- No password strength meter currently

---

## License

This project is open source and available for personal and educational use.
