from cryptography import x509
from cryptography.x509 import (
    DNSName,
    CertificateBuilder,
    NameAttribute,
    SubjectAlternativeName,
)
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Tuple
import datetime


def gen_cert() -> Tuple[bytes, bytes, bytes]:
    SELF_SIGNED_CERT_DOMAIN_NAME = "vt-p2p.colink"
    subject_alt_names = [DNSName(SELF_SIGNED_CERT_DOMAIN_NAME)]
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    builder = CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                NameAttribute(NameOID.COMMON_NAME, "rcgen self signed cert"),
            ]
        )
    )
    builder = builder.issuer_name(
        x509.Name(
            [
                NameAttribute(NameOID.COMMON_NAME, "rcgen self signed cert"),
            ]
        )
    )
    builder = builder.not_valid_before(datetime.datetime(2022, 1, 1))
    builder = builder.not_valid_after(datetime.datetime(4096, 1, 1))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        SubjectAlternativeName(subject_alt_names), critical=False
    )
    cert = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )
    priv_key_pem = private_key.private_bytes(
        Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_der = cert.public_bytes(Encoding.DER)
    cert_pem = cert.public_bytes(Encoding.PEM)
    return cert_der, cert_pem, priv_key_pem
