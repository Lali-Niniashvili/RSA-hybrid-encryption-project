# RSA-hybrid-encryption-project
# RSA Hybrid Encryption Demo

This project demonstrates **hybrid RSA-AES encryption with signing** in Python.

- RSA-OAEP is used to encrypt a random AES key
- AES-GCM encrypts the actual message/file
- RSA-PSS signs the ciphertext for integrity and authenticity

---

## Requirements

```bash
pip install -r requirements.txt
