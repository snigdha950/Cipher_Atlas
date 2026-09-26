from __future__ import annotations

import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from .evidence import measured_probe

TARGET = "X25519MLKEM768"


def _openssl_version() -> str:
    try:
        r = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=3)
        return r.stdout.strip() or r.stderr.strip() or "unavailable"
    except Exception:
        return "unavailable"


def _supports_target() -> bool:
    try:
        r = subprocess.run(["openssl", "list", "-tls-groups"], capture_output=True, text=True, timeout=4)
        return r.returncode == 0 and TARGET in r.stdout
    except Exception:
        return False


def local_probe_capability() -> dict:
    return {
        "openssl_path": shutil.which("openssl"),
        "openssl_version": _openssl_version(),
        "supports_target": _supports_target() if shutil.which("openssl") else False,
        "target": TARGET,
    }


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def live_local_probe(server_groups: str = TARGET) -> dict:
    """Run only CipherAtlas' own temporary OpenSSL harness on loopback.

    It never builds or executes scanned repository code and opens no external network connection.
    """
    version = _openssl_version()
    if shutil.which("openssl") is None or not _supports_target():
        return {
            "status": "INCONCLUSIVE",
            "mode": "LIVE_LOCAL",
            "reason": "Local OpenSSL does not expose X25519MLKEM768.",
            "openssl_version": version,
            "scope": "No repository code was executed.",
        }

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        key, cert = d / "server.key", d / "server.crt"
        gen = subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-keyout", str(key), "-out", str(cert), "-nodes", "-subj", "/CN=localhost", "-days", "1"
        ], capture_output=True, text=True, timeout=10)
        if gen.returncode != 0:
            return {
                "status": "INCONCLUSIVE", "mode": "LIVE_LOCAL",
                "reason": (gen.stderr or gen.stdout)[-500:], "openssl_version": version,
                "scope": "Temporary loopback harness; repository code not executed.",
            }

        port = _free_loopback_port()
        srv_cmd = [
            "openssl", "s_server", "-accept", str(port), "-cert", str(cert), "-key", str(key),
            "-groups", server_groups, "-tls1_3", "-naccept", "1", "-quiet"
        ]
        srv = subprocess.Popen(
            srv_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        time.sleep(0.4)
        cli_cmd = [
            "openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "localhost",
            "-CAfile", str(cert), "-verify_return_error"
        ]
        try:
            r = subprocess.run(cli_cmd, input="Q\n", capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            srv.kill()
            srv.wait()
            return {
                "status": "INCONCLUSIVE", "mode": "LIVE_LOCAL", "reason": "Probe timed out",
                "openssl_version": version,
                "scope": "Temporary loopback harness; repository code not executed.",
            }
        finally:
            if srv.poll() is None:
                srv.kill()
                srv.wait()

        raw = (r.stdout or "") + "\n" + (r.stderr or "")
        grp = (
            re.search(r"Negotiated TLS1\.3 group: (\S+)", raw)
            or re.search(r"(?:Server|Peer) Temp Key: ([^,\n]+)", raw)
        )
        verify_ok = "Verify return code: 0 (ok)" in raw
        handshake_ok = r.returncode == 0 and verify_ok
        return {
            "status": "COMPLETE",
            "mode": "LIVE_LOCAL",
            "client": "local-system-openssl",
            "openssl_version": version,
            "server_groups": server_groups,
            "handshake_ok": handshake_ok,
            "negotiated_group": grp.group(1).strip() if grp else None,
            "exit_code": r.returncode,
            "command": " ".join(cli_cmd),
            "server_command": " ".join(srv_cmd),
            "raw_output": raw[-5000:],
            "scope": "Loopback-only CipherAtlas harness using local OpenSSL and a temporary ECDSA certificate. Repository code was not executed.",
        }


def run_probe(client: str, server_config: str) -> dict:
    groups = {
        "hybrid_only": TARGET,
        "hybrid_with_classical_fallback": f"{TARGET}:X25519",
        "classical_only": "X25519",
    }.get(server_config, TARGET)

    if client == "local-system-openssl":
        return live_local_probe(groups)

    record = measured_probe(client, server_config)
    if record:
        record["reproduce"] = "python -m research.phase0.probes.tls_probes"
        return record

    return {
        "status": "INCONCLUSIVE",
        "mode": "NO_EVIDENCE",
        "reason": "No matching measured stack profile exists for this client/configuration.",
        "scope": "No inference is substituted for missing evidence.",
    }
