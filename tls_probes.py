"""Gate 1: real TLS probes against library twins built from source.

Twins (exact library versions):
  3.5.4  -> /opt/twins/openssl-3.5.4   (built from the GitHub release tarball, sha256 checked)
  3.0.13 -> system /usr/bin/openssl    (Ubuntu 24.04 package)
  1.1.1w -> /opt/twins/openssl-1.1.1w  (built from the GitHub release tarball, sha256 checked)

All traffic is loopback-only. No external hosts are contacted.
Usage: python -m phase0.probes.tls_probes --out phase0/results/tls_probes.json
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

TWINS = {
    "openssl-3.5.4": ("/opt/twins/openssl-3.5.4/bin/openssl", "/opt/twins/openssl-3.5.4/lib"),
    "openssl-3.0.13": ("/usr/bin/openssl", ""),
    "openssl-1.1.1w": ("/opt/twins/openssl-1.1.1w/bin/openssl", "/opt/twins/openssl-1.1.1w/lib"),
}
SERVER = "openssl-3.5.4"
SERVER_CONFIGS = {
    "hybrid_only": "X25519MLKEM768",
    "hybrid_with_classical_fallback": "X25519MLKEM768:X25519",
    "mlkem1024_only": "MLKEM1024",
    "classical_only": "X25519",
}
_port = itertools.count(24400)


def _env(twin: str) -> dict[str, str]:
    env = {"PATH": "/usr/bin:/bin"}
    lib = TWINS[twin][1]
    if lib:
        env["LD_LIBRARY_PATH"] = lib
    return env


def ossl(twin: str, *args: str, inp: bytes | None = None, timeout: float = 20) -> subprocess.CompletedProcess:
    return subprocess.run([TWINS[twin][0], *args], input=inp, capture_output=True, timeout=timeout, env=_env(twin))


def make_pki(d: Path) -> dict[str, dict[str, str]]:
    """CA + server cert for each signature algorithm, all made with the 3.5.4 twin."""
    out: dict[str, dict[str, str]] = {}
    for alg, keyargs in {"ecdsa-p256": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
                         "ml-dsa-65": ["-algorithm", "ML-DSA-65"]}.items():
        ca_key, ca_crt = d / f"{alg}-ca.key", d / f"{alg}-ca.crt"
        sk, csr, crt = d / f"{alg}-srv.key", d / f"{alg}-srv.csr", d / f"{alg}-srv.crt"
        for k in (ca_key, sk):
            r = ossl(SERVER, "genpkey", *keyargs, "-out", str(k))
            assert r.returncode == 0, r.stderr
        r = ossl(SERVER, "req", "-x509", "-new", "-key", str(ca_key), "-subj", f"/CN=Test CA {alg}",
                 "-days", "2", "-out", str(ca_crt))
        assert r.returncode == 0, r.stderr
        r = ossl(SERVER, "req", "-new", "-key", str(sk), "-subj", "/CN=localhost", "-out", str(csr))
        assert r.returncode == 0, r.stderr
        ext = d / "ext.cnf"
        ext.write_text("subjectAltName=DNS:localhost\n")
        r = ossl(SERVER, "x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
                 "-CAcreateserial", "-days", "2", "-extfile", str(ext), "-out", str(crt))
        assert r.returncode == 0, r.stderr
        out[alg] = {"ca": str(ca_crt), "key": str(sk), "crt": str(crt),
                    "cert_der_bytes": str(len(ossl(SERVER, "x509", "-in", str(crt), "-outform", "DER").stdout))}
    return out


def handshake(client: str, server_groups: str, pki: dict[str, str], client_groups: str | None = None,
              dual: dict[str, str] | None = None) -> dict:
    """dual: a second (e.g. ECDSA) cert served alongside pki's cert; the server picks per client sigalgs."""
    port = next(_port)
    extra = ["-dcert", dual["crt"], "-dkey", dual["key"]] if dual else []
    srv = subprocess.Popen(
        [TWINS[SERVER][0], "s_server", "-accept", str(port), "-cert", pki["crt"], "-key", pki["key"], *extra,
         "-groups", server_groups, "-tls1_3", "-naccept", "1", "-quiet"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_env(SERVER))
    time.sleep(0.4)
    args = ["s_client", "-connect", f"127.0.0.1:{port}", "-servername", "localhost", "-CAfile", pki["ca"],
            "-verify_return_error", "-msg"]
    if client_groups:
        args += ["-groups", client_groups]
    try:
        r = ossl(client, *args, inp=b"Q\n", timeout=15)
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        rc = r.returncode
    except subprocess.TimeoutExpired:
        out, rc = "TIMEOUT", -1
    finally:
        srv.kill()
        srv.wait()
    ch = re.search(r">>> TLS 1\.[0-3],? ?Handshake \[length ([0-9a-fA-F]+)\], ClientHello", out)
    sig = re.search(r"Peer signature type: (\S+)", out)
    grp = re.search(r"Negotiated TLS1\.3 group: (\S+)", out) or re.search(
        r"(?:Server|Peer) Temp Key: ([^,\n]+)", out
    )
    verify_ok = "Verify return code: 0 (ok)" in out
    established = rc == 0 and ("Cipher is" in out and "(NONE)" not in out.split("Cipher is", 1)[1][:10])
    return {
        "client": client,
        "server_groups": server_groups,
        "client_groups": client_groups or "library default",
        "handshake_ok": bool(established and verify_ok),
        "negotiated_group": grp.group(1).strip() if grp else None,
        "clienthello_bytes": int(ch.group(1), 16) if ch else None,
        "peer_signature_type": sig.group(1) if sig else None,
        "exit_code": rc,
        "error_hint": next((ln.strip() for ln in out.splitlines() if "error" in ln.lower() or "alert" in ln.lower()), None),
    }


def capabilities(twin: str) -> dict:
    v = ossl(twin, "version").stdout.decode().strip()
    kem = ossl(twin, "list", "-kem-algorithms").stdout.decode()
    sig = ossl(twin, "list", "-signature-algorithms").stdout.decode()
    grp = ossl(twin, "list", "-tls-groups")
    return {
        "version": v,
        "ml_kem": "ML-KEM-768" in kem,
        "ml_dsa": "ML-DSA-65" in sig,
        "slh_dsa": "SLH-DSA" in sig,
        "tls_groups": grp.stdout.decode().strip() if grp.returncode == 0 else "list -tls-groups unsupported",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="phase0/results/tls_probes.json")
    a = ap.parse_args()
    res: dict = {"twins": {}, "pki": {}, "handshakes": []}
    for t in TWINS:
        res["twins"][t] = capabilities(t)
    with tempfile.TemporaryDirectory() as td:
        pki = make_pki(Path(td))
        res["pki"] = {k: {"cert_der_bytes": int(v["cert_der_bytes"])} for k, v in pki.items()}
        for cert_alg, cfg, client in itertools.product(pki, SERVER_CONFIGS, TWINS):
            h = handshake(client, SERVER_CONFIGS[cfg], pki[cert_alg])
            h.update({"cert_alg": cert_alg, "server_config": cfg})
            res["handshakes"].append(h)
        # transition: ML-DSA-65 cert + ECDSA cert on one server; clients trust both CAs
        both = Path(td) / "both-ca.pem"
        both.write_text(Path(pki["ml-dsa-65"]["ca"]).read_text() + Path(pki["ecdsa-p256"]["ca"]).read_text())
        dual_pki = dict(pki["ml-dsa-65"], ca=str(both))
        for client in TWINS:
            h = handshake(client, SERVER_CONFIGS["hybrid_with_classical_fallback"], dual_pki, dual=pki["ecdsa-p256"])
            h.update({"cert_alg": "dual:ml-dsa-65+ecdsa-p256", "server_config": "hybrid_with_classical_fallback"})
            res["handshakes"].append(h)
        # ClientHello size comparison with explicit client groups on the 3.5.4 twin
        for g in ("X25519", "X25519MLKEM768", "MLKEM1024", "SecP384r1MLKEM1024"):
            h = handshake(SERVER, g, pki["ecdsa-p256"], client_groups=g)
            h.update({"cert_alg": "ecdsa-p256", "server_config": f"size_probe_{g}"})
            res["handshakes"].append(h)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=1))
    for h in res["handshakes"]:
        print(f'{h["cert_alg"]:11} {h["server_config"]:32} {h["client"]:15} ok={h["handshake_ok"]!s:5} '
              f'group={h["negotiated_group"]} CH={h["clienthello_bytes"]} hint={h["error_hint"]}')


if __name__ == "__main__":
    main()
