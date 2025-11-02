
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# -------- RSA Key Generation --------
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )
    public_key = private_key.public_key()

    # Export PEM
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"strong-passphrase")
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem

# -------- Hybrid Encryption --------
def hybrid_encrypt(plaintext: bytes, recipient_pubkey):
    # AES key and nonce
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)

    # AES encrypt
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    # RSA-OAEP encrypt AES key
    encrypted_key = recipient_pubkey.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "enc_key": encrypted_key,
        "iv": iv,
        "ciphertext": ciphertext
    }

# -------- Hybrid Decryption --------
def hybrid_decrypt(package: dict, recipient_privkey):
    aes_key = recipient_privkey.decrypt(
        package["enc_key"],
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(package["iv"], package["ciphertext"], None)
    return plaintext

# -------- Signing --------
def sign_message(message: bytes, signer_privkey):
    return signer_privkey.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(message: bytes, signature: bytes, signer_pubkey):
    try:
        signer_pubkey.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# -------- Example Usage --------
if __name__ == "__main__":
    # Generate keys (or load from files)
    priv_pem, pub_pem = generate_rsa_keypair()
    private_key = serialization.load_pem_private_key(priv_pem, password=b"strong-passphrase")
    public_key = serialization.load_pem_public_key(pub_pem)

    message = b"This is a secret message."

    # Encrypt and sign
    package = hybrid_encrypt(message, public_key)
    signature = sign_message(package["ciphertext"], private_key)

    # Verify and decrypt
    is_valid = verify_signature(package["ciphertext"], signature, public_key)
    recovered = hybrid_decrypt(package, private_key)

    print("Signature valid:", is_valid)
    print("Recovered message:", recovered.decode())
