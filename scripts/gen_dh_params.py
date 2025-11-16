# scripts/gen_dh_params.py

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

print("Generating DH parameters (2048-bit)... This may take a moment.")

# Generate new 2048-bit DH parameters
params = dh.generate_parameters(generator=2, key_size=2048)

# Define paths
certs_dir = Path("certs")
certs_dir.mkdir(exist_ok=True)
params_path = certs_dir / "dh_params.pem"

# Save parameters to a PEM file
with params_path.open("wb") as f:
    f.write(params.parameter_bytes(
        serialization.Encoding.PEM,
        serialization.ParameterFormat.PKCS3
    ))

print(f"DH parameters saved to: {params_path}")
