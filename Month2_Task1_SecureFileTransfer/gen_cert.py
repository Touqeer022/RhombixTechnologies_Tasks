"""
gen_cert.py
Cross-platform replacement for gen_cert.sh (works on Windows without
needing bash or the openssl CLI — it uses the same `cryptography` library
already required by the app).

Generates a self-signed TLS certificate for the server's transport layer.
This secures the socket connection itself (defense in depth); the actual
file confidentiality/integrity comes from the E2E AES-GCM + RSA-OAEP layer
in crypto_utils.py, which the server can never decrypt regardless of the
transport.

For real deployments, replace this with a certificate from a trusted CA
(e.g. Let's Encrypt) instead of a self-signed one.
"""

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

SERVER_DATA = os.path.join(os.path.dirname(__file__), "server_data")


def main():
    os.makedirs(SERVER_DATA, exist_ok=True)
    cert_path = os.path.join(SERVER_DATA, "server.crt")
    key_path = os.path.join(SERVER_DATA, "server.key")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated {cert_path} and {key_path}")


if __name__ == "__main__":
    main()
