"""Generate a self-signed TLS certificate for the dashboard.

Usage: python scripts\\make_cert.py [--out certs] [--days 1095]
The certificate covers the hostname, FQDN, localhost and every IPv4 address
of this machine, so browsers on the LAN can connect by name or IP.
"""
import argparse
import datetime
import ipaddress
import socket
from pathlib import Path

import psutil
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "certs"))
    ap.add_argument("--days", type=int, default=1095)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    host = socket.gethostname()
    names = {host, host.lower(), socket.getfqdn(), "localhost"}
    ips = {ipaddress.ip_address("127.0.0.1")}
    for addrs in psutil.net_if_addrs().values():
        for ad in addrs:
            if ad.family == socket.AF_INET:
                ips.add(ipaddress.ip_address(ad.address))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AI Server Dashboard")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=a.days))
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName(n) for n in sorted(names) if n] + [x509.IPAddress(i) for i in sorted(ips)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    (out / "server.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    (out / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"wrote {out / 'server.crt'} for {', '.join(sorted(names))} / {', '.join(map(str, sorted(ips)))}")


if __name__ == "__main__":
    main()
