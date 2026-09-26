"""Gate 1b: does a verifier ENFORCE the post-quantum half of a Catalyst-style hybrid certificate?

We build leaf certificates signed classically (ECDSA P-256) that carry the X.509 alternative-
signature extensions (2.5.29.72 subjectAltPublicKeyInfo, .73 altSignatureAlgorithm,
.74 altSignatureValue) with ML-DSA-65 content:

  valid_alt      alt signature = ML-DSA-65 over the DER TBSCertificate built WITHOUT ext .74
                 (an approximation of the X.509 preTBSCertificate; enough for legacy verifiers,
                 NOT claimed to be conformant for PQ-aware verifiers)
  forged_alt     alt signature = random bytes
  stripped       no alternative-signature extensions at all
  forged_crit    forged alt signature, extensions marked CRITICAL

Verifiers: the three OpenSSL twins plus pyca/cryptography 50 (bundled OpenSSL 4.0.2) path validation.
Keys are generated per run and discarded. Nothing leaves the machine.

LIMITATION: Bouncy Castle and wolfSSL (the PQ-aware verifiers studied in ePrint 2026/1416) are
not available in this environment (Maven Central blocked). This probe therefore tests only the
legacy-verifier behaviour, not the paper's main finding.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa
from cryptography.x509.oid import NameOID

from .tls_probes import TWINS, _env

OID_ALT_SPKI = x509.ObjectIdentifier("2.5.29.72")
OID_ALT_ALG = x509.ObjectIdentifier("2.5.29.73")
OID_ALT_SIG = x509.ObjectIdentifier("2.5.29.74")
MLDSA65_ALGID = bytes.fromhex("300b0609608648016503040312")


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _bitstring(data: bytes) -> bytes:
    body = b"\x00" + data
    return b"\x03" + _der_len(len(body)) + body


def build(variant: str, ca_key, ca_name, alt_key) -> x509.Certificate:
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    base = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )
    if variant == "stripped":
        return base.sign(ca_key, hashes.SHA256())
    crit = variant == "forged_crit"
    alt_spki = alt_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pre = base.add_extension(x509.UnrecognizedExtension(OID_ALT_SPKI, alt_spki), critical=crit).add_extension(
        x509.UnrecognizedExtension(OID_ALT_ALG, MLDSA65_ALGID), critical=crit
    )
    if variant == "valid_alt":
        pre_tbs = pre.sign(ca_key, hashes.SHA256()).tbs_certificate_bytes
        alt_sig = alt_key.sign(pre_tbs)
    else:
        alt_sig = os.urandom(3309)  # ML-DSA-65 signature length
    return pre.add_extension(x509.UnrecognizedExtension(OID_ALT_SIG, _bitstring(alt_sig)), critical=crit).sign(
        ca_key, hashes.SHA256()
    )


def verify_openssl(twin: str, ca: Path, leaf: Path) -> tuple[bool, str]:
    r = subprocess.run([TWINS[twin][0], "verify", "-CAfile", str(ca), str(leaf)],
                       capture_output=True, text=True, env=_env(twin), timeout=20)
    msg = (r.stdout + r.stderr).strip().splitlines()
    return r.returncode == 0, msg[-1] if msg else ""


def verify_pyca(ca_cert: x509.Certificate, leaf: x509.Certificate) -> tuple[bool, str]:
    from cryptography.x509.verification import PolicyBuilder, Store

    try:
        verifier = PolicyBuilder().store(Store([ca_cert])).build_server_verifier(x509.DNSName("localhost"))
        verifier.verify(leaf, [])
        return True, "ok"
    except Exception as e:  # report, never swallow silently
        return False, f"{type(e).__name__}: {e}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="phase0/results/catalyst_probe.json")
    a = ap.parse_args()
    ca_key = ec.generate_private_key(ec.SECP256R1())
    alt_key = mldsa.MLDSA65PrivateKey.generate()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Catalyst Test CA")])
    now = dt.datetime.now(dt.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    rows = []
    with tempfile.TemporaryDirectory() as td:
        ca_p = Path(td) / "ca.pem"
        ca_p.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        for variant in ("stripped", "valid_alt", "forged_alt", "forged_crit"):
            leaf = build(variant, ca_key, ca_name, alt_key)
            lp = Path(td) / f"{variant}.pem"
            lp.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
            size = len(leaf.public_bytes(serialization.Encoding.DER))
            for twin in TWINS:
                ok, msg = verify_openssl(twin, ca_p, lp)
                rows.append({"variant": variant, "verifier": twin, "accepted": ok, "detail": msg, "cert_der_bytes": size})
            ok, msg = verify_pyca(ca_cert, leaf)
            rows.append({"variant": variant, "verifier": "pyca-cryptography-50", "accepted": ok,
                         "detail": msg, "cert_der_bytes": size})
    Path(a.out).write_text(json.dumps(rows, indent=1))
    for r in rows:
        print(f'{r["variant"]:12} {r["verifier"]:22} accepted={r["accepted"]!s:5} size={r["cert_der_bytes"]} {r["detail"][:70]}')


if __name__ == "__main__":
    main()
