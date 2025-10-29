import pathlib, subprocess, tempfile, ssl, ipaddress
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ---------------------------
# Ruta de salida
# ---------------------------
CERT_DIR = pathlib.Path("certs")
CERT_DIR.mkdir(exist_ok=True)

# ---------------------------
# Crear CA (autoridad raíz)
# ---------------------------
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MiniCA-Local")])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow() - timedelta(days=1))
    .not_valid_after(datetime.utcnow() + timedelta(days=1825))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(private_key=ca_key, algorithm=hashes.SHA256())
)

(CERT_DIR / "ca.key").write_bytes(
    ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
)
(CERT_DIR / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

# ---------------------------
# Crear servidor firmado por la CA
# ---------------------------
server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_name)
    .issuer_name(ca_name)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow() - timedelta(days=1))
    .not_valid_after(datetime.utcnow() + timedelta(days=825))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        ),
        critical=False,
    )
    .sign(private_key=ca_key, algorithm=hashes.SHA256())
)

(CERT_DIR / "server.key").write_bytes(
    server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
)
(CERT_DIR / "server.crt").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

print("✅ Certificados generados en ./certs:")
for f in CERT_DIR.iterdir():
    print("  -", f)
