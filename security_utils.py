# security_utils.py

import os
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidSignature, InvalidTag

CERTS_DIR = Path("certs")

# --- 1. Certificate and Key Loading ---

def load_ca_cert():
    """Loads the CA's root certificate."""
    with (CERTS_DIR / "ca.crt.pem").open("rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def load_cert(name):
    """Loads an entity's certificate (e.g., 'server' or 'client')."""
    with (CERTS_DIR / f"{name}.crt.pem").open("rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def load_private_key(name):
    """Loads an entity's private key."""
    with (CERTS_DIR / f"{name}.key").open("rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

# --- 2. Certificate Verification (Requirement 2.1) ---

def verify_peer_cert(peer_cert, ca_cert, expected_cn):
    """
    Verifies a peer's certificate.
    - Checks it was signed by our CA.
    - Checks it's not expired.
    - Checks the Common Name (CN) is what we expect.
    """
    print(f"Verifying cert for CN={peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value}...")

    # Check signature
    try:
        ca_cert.public_key().verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            peer_cert.signature_hash_algorithm,
        )
        print("  ✅ Signature OK (Issued by our CA)")
    except InvalidSignature:
        print("  ❌ INVALID SIGNATURE! Cert not issued by our CA.")
        return False

    # Check expiry
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (peer_cert.not_valid_before_utc <= now <= peer_cert.not_valid_after_utc):
        print(f"  ❌ CERTIFICATE EXPIRED! Valid from {peer_cert.not_valid_before_utc} to {peer_cert.not_valid_after_utc}")
        return False
    print("  ✅ Validity Period OK")

    # Check Common Name
    cn = peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    if cn != expected_cn:
        print(f"  ❌ WRONG COMMON NAME! Expected '{expected_cn}', got '{cn}'")
        return False
    print(f"  ✅ Common Name OK ('{cn}')")

    print(f"Certificate for '{expected_cn}' is VALID.\n")
    return True

# --- 3. Diffie-Hellman (DH) Key Exchange (Req 2.2, 2.3) ---

# Use standard DH parameters (Group 14) for simplicity
def load_dh_parameters():
    """Loads the pre-generated DH parameters from a file."""
    try:
        with (CERTS_DIR / "dh_params.pem").open("rb") as f:
            return serialization.load_pem_parameters(f.read(), default_backend())
    except FileNotFoundError:
        print("ERROR: dh_params.pem not found. Run 'python3 scripts/gen_dh_params.py' first.")
        exit(1)

# Load the parameters ONCE when the module is imported
DH_PARAMS = load_dh_parameters()

def dh_generate_keys():
    """Generates a new DH private/public key pair."""
    private_key = DH_PARAMS.generate_private_key()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_bytes

def dh_derive_shared_secret(private_key, peer_public_bytes):
    """Derives the shared secret from peer's public key."""
    peer_public_key = serialization.load_pem_public_key(
        peer_public_bytes,
        default_backend()
    )
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret

# --- 4. Key Derivation (Req 2.2, 2.3) ---

def derive_key_from_dh_secret(secret):
    """
    Implements K = Trunc_16(SHA256(big-endian(K_s)))
    """
    # SHA256 hash
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(secret)
    hashed_secret = digest.finalize()

    # Truncate to 16 bytes (128 bits)
    aes_key = hashed_secret[:16]
    return aes_key


# --- 5. AES-CBC Encryption (Req 2.2, 2.4) ---

def pad(data):
    """Pads data to 128-bit block size using PKCS#7."""
    padder = PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data) + padder.finalize()

def unpad(padded_data):
    """Removes PKCS#7 padding."""
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def encrypt_aes_cbc(key, plaintext):
    """
    Encrypts plaintext using AES-128-CBC with PKCS#7 padding.
    Returns a single bytestring: iv + ciphertext
    """
    iv = os.urandom(16) # A new random IV for every encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padded_plaintext = pad(plaintext)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + ciphertext

def decrypt_aes_cbc(key, iv_ciphertext):
    """
    Decrypts iv + ciphertext from AES-128-CBC.
    """
    # Split the IV and the ciphertext
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    try:
        plaintext = unpad(padded_plaintext)
        return plaintext
    except ValueError:
        print("DECRYPTION ERROR: Invalid padding. Data may be corrupt or key is wrong.")
        return None

# --- 6. Hashing and Signatures (Req 2.2, 2.4, 2.5) ---

def hash_sha256(data):
    """Computes a SHA-256 hash."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def sign(private_key, data):
    """
    Signs data with an RSA private key.
    (Using PSS padding as it's more secure, but PKCS1v15 is also fine)
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key, signature, data):
    """
    Verifies an RSA signature.
    Returns True if valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# --- 7. Database Password Hashing (Req 2.2) ---

def hash_password(password, salt):
    """
    Computes SHA256(salt || password)
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(salt)
    digest.update(password.encode('utf-8'))
    return digest.finalize().hex() # Return as hex string

def generate_salt():
    """Generates a 16-byte random salt."""
    return os.urandom(16)
