# scripts/gen_ca.py

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

def main():
    """
    Creates a new self-signed root CA key and certificate.
    """
    print("Generating root CA...")
   
    # --- Create certs directory if it doesn't exist ---
    certs_dir = Path("certs")
    certs_dir.mkdir(exist_ok=True)
   
    ca_key_path = certs_dir / "ca.key"
    ca_cert_path = certs_dir / "ca.crt.pem"
   
    # --- Generate CA Private Key ---
    print("Generating CA private key...")
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,  # 4096-bit key for strong security
        backend=default_backend()
    )
   
    # --- Save CA Private Key ---
    print(f"Saving CA private key to {ca_key_path}")
    with ca_key_path.open("wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
   
    # --- Create CA Certificate ---
    print("Creating self-signed CA certificate...")
   
    # Define the subject
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Secure Chat"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MySecureChatRootCA"),
    ])
   
    # Root certs are self-signed, so issuer == subject
    issuer_name = subject_name
   
    # Set validity (e.g., 10 years)
    not_valid_before = datetime.datetime.now(datetime.timezone.utc)
    not_valid_after = not_valid_before + datetime.timedelta(days=365 * 10)
   
    # Build the certificate
    builder = x509.CertificateBuilder().subject_name(
        subject_name
    ).issuer_name(
        issuer_name
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    ).add_extension(  # This extension identifies it as a CA
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
   
    # Sign the certificate with its own private key
    ca_certificate = builder.sign(
        ca_private_key, hashes.SHA256(), default_backend()
    )
   
    # --- Save CA Certificate ---
    print(f"Saving CA certificate to {ca_cert_path}")
    with ca_cert_path.open("wb") as f:
        f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))
       
    print("\nRoot CA generated successfully!")
    print(f"Key:    {ca_key_path}")
    print(f"Cert:   {ca_cert_path}")

if __name__ == "__main__":
    main()
