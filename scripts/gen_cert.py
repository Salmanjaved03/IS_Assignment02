# scripts/gen_cert.py

import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

def main():
    """
    Issues a new certificate signed by the root CA.
   
    Usage: python3 scripts/gen_cert.py <name> <common_name>
    Example: python3 scripts/gen_cert.py server localhost
    """
    # --- Check and get arguments ---
    if len(sys.argv) != 3:
        print("Usage: python3 scripts/gen_cert.py <name> <common_name>")
        print("Example: python3 scripts/gen_cert.py server localhost")
        sys.exit(1)
       
    name = sys.argv[1]
    common_name = sys.argv[2]
   
    print(f"Generating certificate for '{name}' with CN='{common_name}'...")
   
    # --- Define file paths ---
    certs_dir = Path("certs")
    ca_key_path = certs_dir / "ca.key"
    ca_cert_path = certs_dir / "ca.crt.pem"
   
    key_path = certs_dir / f"{name}.key"
    cert_path = certs_dir / f"{name}.crt.pem"
   
    # --- Load CA Key and Certificate ---
    print("Loading CA key and certificate...")
    try:
        ca_private_key = serialization.load_pem_private_key(
            ca_key_path.read_bytes(),
            password=None,
            backend=default_backend()
        )
        ca_certificate = x509.load_pem_x509_certificate(
            ca_cert_path.read_bytes(),
            default_backend()
        )
    except FileNotFoundError:
        print(f"Error: CA files not found. Did you run gen_ca.py first?")
        sys.exit(1)

    # --- Generate New Private Key ---
    print(f"Generating private key for '{name}'...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # 2048-bit key is standard for end-entities
        backend=default_backend()
    )
   
    # --- Save New Private Key ---
    print(f"Saving key to {key_path}")
    with key_path.open("wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
       
    # --- Create Certificate ---
    print("Creating signed certificate...")
   
    # Define the subject
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Secure Chat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
   
    # Issuer is the CA's subject
    issuer_name = ca_certificate.subject
   
    # Set validity (e.g., 1 year)
    not_valid_before = datetime.datetime.now(datetime.timezone.utc)
    not_valid_after = not_valid_before + datetime.timedelta(days=365)
   
    # Build the certificate
    builder = x509.CertificateBuilder().subject_name(
        subject_name
    ).issuer_name(
        issuer_name
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    ).add_extension(  # Not a CA
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(  # Key Usage: Digital Signature and Key Encipherment (for RSA)
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True
    ).add_extension( # Subject Alternative Name (SAN) - Required by modern clients
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False
    )
   
    # Sign the certificate with the CA's private key
    certificate = builder.sign(
        ca_private_key, hashes.SHA256(), default_backend()
    )
   
    # --- Save Certificate ---
    print(f"Saving certificate to {cert_path}")
    with cert_path.open("wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"\nCertificate for '{name}' generated successfully!")
    print(f"Key:    {key_path}")
    print(f"Cert:   {cert_path}")

if __name__ == "__main__":
    main()
