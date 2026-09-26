from app.scanner import scan_entries
from app.security import ArchiveEntry


def test_comment_only_rsa_is_not_active():
    r = scan_entries([ArchiveEntry("a.py", b"# RSA is no longer used\nprint('ok')\n", True)])
    assert not any(f["algorithm"] == "RSA" for f in r["findings"])


def test_rsa_signature_is_purpose_aware():
    src = b"""from cryptography.hazmat.primitives.asymmetric import rsa\n\ndef f(k: rsa.RSAPrivateKey,p):\n    return k.sign(p)\n"""
    r = scan_entries([ArchiveEntry("sign.py", src, True)])
    assert any(f["algorithm"] == "RSA" and f["purpose"] == "digital signature" for f in r["findings"])


def test_scan_incomplete_when_unsupported_file_present():
    r = scan_entries([ArchiveEntry("a.py", b"print('ok')", True), ArchiveEntry("blob.bin", b"x", False)])
    assert r["coverage"]["status"] == "SCAN_INCOMPLETE"
    assert r["coverage"]["unsupported_files"] == 1


def test_config_finds_hybrid_group():
    r = scan_entries([ArchiveEntry("tls.conf", b"Protocol = TLSv1.3\nGroups = X25519MLKEM768:X25519\n", True)])
    algs = {f["algorithm"] for f in r["findings"]}
    assert "X25519MLKEM768" in algs
    assert "X25519" in algs


def test_unrelated_sign_call_not_mislabeled_rsa():
    src = b"""from cryptography.hazmat.primitives.asymmetric import rsa\n\nclass Other:\n    def sign(self, x): return x\n\ndef f(o):\n    return o.sign(b'x')\n"""
    r = scan_entries([ArchiveEntry("other.py", src, True)])
    assert not any(f["algorithm"] == "RSA" and f["purpose"] == "digital signature" for f in r["findings"])


def test_aliased_rsa_key_annotation_is_detected():
    src = b"""from cryptography.hazmat.primitives.asymmetric import rsa as r\n\ndef f(k: r.RSAPrivateKey, p: bytes):\n    return k.sign(p, None, None)\n"""
    r = scan_entries([ArchiveEntry("alias.py", src, True)])
    assert any(f["algorithm"] == "RSA" and f["purpose"] == "digital signature" for f in r["findings"])


def test_openssl_version_is_inventoried():
    r = scan_entries([ArchiveEntry("tls.conf", b"OpenSSLVersion = 3.5.4\n", True)])
    assert any(f["algorithm"] == "OpenSSL" and f["version"] == "3.5.4" for f in r["findings"])
