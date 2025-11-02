import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------- RSA Key Generation --------
def generate_rsa_keypair(passphrase: bytes = b"mypassword"):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem

# -------- Hybrid Encryption --------
def encrypt_message(message: str, recipient_pubkey):
    aes_key = AESGCM.generate_key(bit_length=128)  # beginner-friendly AES-128
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, message.encode(), None)

    enc_key = recipient_pubkey.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {"enc_key": enc_key, "iv": iv, "ciphertext": ciphertext}

# -------- Decryption --------
def decrypt_message(package: dict, recipient_privkey, passphrase: bytes = b"mypassword"):
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
    return plaintext.decode()

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

# -------- Demo --------
if __name__ == "__main__":
    # Alice generates keys
    alice_priv_pem, alice_pub_pem = generate_rsa_keypair()
    alice_private_key = serialization.load_pem_private_key(alice_priv_pem, password=b"mypassword")
    alice_public_key = serialization.load_pem_public_key(alice_pub_pem)

    # Bob generates keys
    bob_priv_pem, bob_pub_pem = generate_rsa_keypair()
    bob_private_key = serialization.load_pem_private_key(bob_priv_pem, password=b"mypassword")
    bob_public_key = serialization.load_pem_public_key(bob_pub_pem)

    # Alice sends a message to Bob
    message = "Hello Bob, this is Alice."
    package = encrypt_message(message, bob_public_key)
    signature = sign_message(package["ciphertext"], alice_private_key)

    # Bob verifies signature and decrypts
    valid = verify_signature(package["ciphertext"], signature, alice_public_key)
    decrypted_message = decrypt_message(package, bob_private_key)

    print("Signature valid:", valid)
    print("Decrypted message:", decrypted_message)

