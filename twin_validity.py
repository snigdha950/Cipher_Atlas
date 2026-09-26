"""Gate 2 pilot: does a library-version twin predict what a REAL third-party app does?

Apps (none written by us; each links a TLS library we can identify statically):
  curl 8.5.0            -> links OpenSSL 3.0.13       -> twin openssl-3.0.13
  python3 ssl (system)  -> links OpenSSL 3.0.13       -> twin openssl-3.0.13
  node 22.22.2          -> bundles OpenSSL 3.5.5      -> nearest twin openssl-3.5.4
  java 21 JSSE          -> no OpenSSL                 -> no twin (prediction UNKNOWN)

Each app connects to the openssl-3.5.4 server under the same configs used in tls_probes.
Prediction = the twin's s_client result for the same (cert, config) from tls_probes.json.
Usage: python -m phase0.probes.twin_validity --probes phase0/results/tls_probes.json
"""

from __future__ import annotations

import argparse
import itertools
import json
import subprocess
import tempfile
import time
from pathlib import Path

from .tls_probes import SERVER, SERVER_CONFIGS, TWINS, _env, make_pki

_port = itertools.count(25400)

PY_CLIENT = """
import socket, ssl, sys
ctx = ssl.create_default_context(cafile=sys.argv[2])
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10) as s:
    with ctx.wrap_socket(s, server_hostname="localhost") as t:
        t.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n"); t.recv(64)
print("OK")
"""
NODE_CLIENT = """
const tls=require('tls'),fs=require('fs');
const s=tls.connect({host:'127.0.0.1',port:+process.argv[2],servername:'localhost',ca:fs.readFileSync(process.argv[3])},()=>{
  const k=s.getEphemeralKeyInfo(); console.log('OK', k && (k.name||k.type)); s.end(); process.exit(0)});
s.on('error',e=>{console.log('ERR',e.code||e.message); process.exit(1)});
"""
JAVA_CLIENT = """
import javax.net.ssl.*; import java.io.*; import java.security.*; import java.security.cert.*;
public class J { public static void main(String[] a) throws Exception {
  KeyStore ks=KeyStore.getInstance("PKCS12"); ks.load(null,null);
  ks.setCertificateEntry("ca", CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(a[1])));
  TrustManagerFactory tmf=TrustManagerFactory.getInstance("PKIX"); tmf.init(ks);
  SSLContext c=SSLContext.getInstance("TLSv1.3"); c.init(null,tmf.getTrustManagers(),null);
  SSLSocket s=(SSLSocket)c.getSocketFactory().createSocket("localhost",Integer.parseInt(a[0]));
  s.startHandshake(); System.out.println("OK"); s.close(); } }
"""

APPS = {
    "curl-8.5.0": "openssl-3.0.13",
    "python3-ssl": "openssl-3.0.13",
    "node-22.22.2": "openssl-3.5.4",
    "java-21-jsse": None,
}


def run_app(app: str, port: int, ca: str, work: Path) -> tuple[bool, str]:
    env = {"PATH": "/usr/bin:/bin:/opt/node22/bin", "HOME": str(work)}
    if app == "curl-8.5.0":
        cmd = ["curl", "-sS", "--max-time", "10", "--cacert", ca, f"https://localhost:{port}/", "-o", "/dev/null"]
    elif app == "python3-ssl":
        cmd = ["/usr/bin/python3", "-c", PY_CLIENT, str(port), ca]
    elif app == "node-22.22.2":
        # with `node -e`, script args start at process.argv[1]
        script = NODE_CLIENT.replace("process.argv[2]", "process.argv[1]").replace("process.argv[3]", "process.argv[2]")
        cmd = ["node", "-e", script, str(port), ca]
    else:
        cmd = ["java", "-cp", str(work), "J", str(port), ca]
        env["JAVA_TOOL_OPTIONS"] = ""
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
    detail = (r.stdout + r.stderr).strip().splitlines()
    return r.returncode == 0, (detail[-1] if detail else "")[:120]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--probes", default="phase0/results/tls_probes.json")
    ap.add_argument("--out", default="phase0/results/twin_validity.json")
    a = ap.parse_args()
    twin_rows = json.loads(Path(a.probes).read_text())["handshakes"]
    pred = {(h["client"], h["cert_alg"], h["server_config"]): h["handshake_ok"] for h in twin_rows}
    rows = []
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        (work / "J.java").write_text(JAVA_CLIENT)
        subprocess.run(["javac", "-d", str(work), str(work / "J.java")], check=True, capture_output=True)
        pki = make_pki(work)
        for cert_alg, cfg, app in itertools.product(pki, SERVER_CONFIGS, APPS):
            port = next(_port)
            srv = subprocess.Popen(
                [TWINS[SERVER][0], "s_server", "-accept", str(port), "-cert", pki[cert_alg]["crt"],
                 "-key", pki[cert_alg]["key"], "-groups", SERVER_CONFIGS[cfg], "-tls1_3", "-www", "-naccept", "1", "-quiet"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=_env(SERVER))
            time.sleep(0.4)
            try:
                ok, detail = run_app(app, port, pki[cert_alg]["ca"], work)
            except subprocess.TimeoutExpired:
                ok, detail = False, "TIMEOUT"
            finally:
                srv.kill()
                srv.wait()
            twin = APPS[app]
            p = pred.get((twin, cert_alg, cfg)) if twin else None
            rows.append({"app": app, "twin": twin, "cert_alg": cert_alg, "server_config": cfg,
                         "predicted_ok": p, "actual_ok": ok, "detail": detail,
                         "outcome": "no_twin" if p is None else ("agree" if p == ok else
                                    ("FALSE_COMPATIBLE" if p and not ok else "false_incompatible"))})
    Path(a.out).write_text(json.dumps(rows, indent=1))
    for r in rows:
        print(f'{r["app"]:13} {r["cert_alg"]:10} {r["server_config"]:31} pred={str(r["predicted_ok"]):5} '
              f'actual={str(r["actual_ok"]):5} {r["outcome"]:18} {r["detail"][:60]}')
    scored = [r for r in rows if r["predicted_ok"] is not None]
    fc = sum(r["outcome"] == "FALSE_COMPATIBLE" for r in scored)
    fi = sum(r["outcome"] == "false_incompatible" for r in scored)
    pred_ok = sum(bool(r["predicted_ok"]) for r in scored)
    print(f"\nscored={len(scored)} agree={len(scored) - fc - fi} false_compatible={fc} "
          f"(rate among predicted-OK: {fc}/{pred_ok}) false_incompatible={fi} no_twin={len(rows) - len(scored)}")


if __name__ == "__main__":
    main()
