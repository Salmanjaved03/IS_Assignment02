# verify_transcript.py

import json
import sys
from pathlib import Path
import security_utils as sec
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 verify_transcript.py <path_to_receipt.json> <path_to_transcript.log>")
        sys.exit(1)

    receipt_path = Path(sys.argv[1])
    transcript_path = Path(sys.argv[2])

    print(f"Verifying Receipt:   {receipt_path.name}")
    print(f"Against Transcript:  {transcript_path.name}")

    # 1. Load Receipt
    try:
        with receipt_path.open("r") as f:
            receipt = json.load(f)
    except Exception as e:
        print(f"Error loading receipt: {e}")
        sys.exit(1)

    # 2. Re-compute Transcript Hash
    try:
        transcript_data = transcript_path.read_bytes()
        computed_hash = sec.hash_sha256(transcript_data)
    except Exception as e:
        print(f"Error loading transcript: {e}")
        sys.exit(1)

    # 3. Compare Hashes
    receipt_hash_hex = receipt['transcript_hash_hex']
    print(f"\nReceipt Hash:  {receipt_hash_hex}")
    print(f"Computed Hash: {computed_hash.hex()}")

    if computed_hash.hex() != receipt_hash_hex:
        print("❌ HASH MISMATCH! Transcript has been tampered with.")
        sys.exit(1)

    print("✅ Hash OK")

    # 4. Verify Signature
    # Figure out who signed it (client or server)
    cert_pem = ""
    if "client_cert" in receipt:
        cert_pem = receipt['client_cert']
        print("Receipt was signed by: CLIENT")
    elif "server_cert" in receipt:
        cert_pem = receipt['server_cert']
        print("Receipt was signed by: SERVER")

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
        public_key = cert.public_key()

        signature = bytes.fromhex(receipt['signature_hex'])

        # We verify the signature was over the *computed* hash
        if sec.verify_signature(public_key, signature, computed_hash):
            print("✅ Signature is VALID.")
        else:
            print("❌ INVALID SIGNATURE! Receipt is a forgery.")
            sys.exit(1)

        print("\n--- VERIFICATION SUCCESSFUL ---")
        print("The transcript is authentic and has not been tampered with.")

    except Exception as e:
        print(f"Error during signature verification: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
