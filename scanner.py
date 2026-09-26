from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, asdict
from pathlib import PurePosixPath
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, ed448

from .security import ArchiveEntry


@dataclass
class Finding:
    kind: str
    algorithm: str
    purpose: str
    concern: str
    path: str
    line: int | None
    evidence: str
    confidence: str = "CONFIRMED"
    library: str | None = None
    version: str | None = None
    key_size: int | None = None
    protocol: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _concern(algorithm: str, purpose: str) -> str:
    u = algorithm.upper()
    if any(x in u for x in ("RSA", "ECDSA", "ECDH", "X25519", "X448")) or u.startswith("EC ("):
        return "Migration-relevant classical public-key cryptography"
    if "ML-KEM" in u or "MLKEM" in u or "ML-DSA" in u or "SLH-DSA" in u:
        return "Post-quantum / transition mechanism"
    if "AES" in u or "SHA-2" in u or "SHA256" in u or "HMAC" in u:
        return "Not treated as quantum-broken; policy-dependent review only"
    if u == "OPENSSL":
        return "Version-specific cryptographic implementation; verify capabilities before migration"
    return "Review context before recommending migration"


def _expr_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _expr_name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def scan_python(path: str, data: bytes) -> tuple[list[Finding], str | None]:
    """Purpose-aware Python scan without executing repository code.

    This is intentionally narrow. It resolves import aliases and tracks obvious key variables,
    avoiding the earlier false-positive pattern of treating every `.sign()` call as RSA merely
    because RSA happened to be imported somewhere in the file.
    """
    try:
        text = data.decode("utf-8")
        tree = ast.parse(text, filename=path)
    except Exception as e:
        return [], f"Python parse failed: {e}"

    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    def resolve(name: str) -> str:
        if not name:
            return name
        root, *rest = name.split(".")
        mapped = aliases.get(root, root)
        return ".".join([mapped, *rest]) if rest else mapped

    rsa_key_vars: set[str] = set()
    x25519_key_vars: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                ann = resolve(_expr_name(arg.annotation)).lower()
                if "rsa" in ann and ("privatekey" in ann or "publickey" in ann):
                    rsa_key_vars.add(arg.arg)
                if "x25519" in ann and ("privatekey" in ann or "publickey" in ann):
                    x25519_key_vars.add(arg.arg)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value if isinstance(node, ast.AnnAssign) else node.value
            if isinstance(value, ast.Call):
                callee = resolve(_expr_name(value.func)).lower()
                targets: list[str] = []
                raw_targets = [node.target] if isinstance(node, ast.AnnAssign) else list(node.targets)
                for t in raw_targets:
                    if isinstance(t, ast.Name):
                        targets.append(t.id)
                if "rsa" in callee and "generate_private_key" in callee:
                    rsa_key_vars.update(targets)
                if "x25519" in callee and ("generate" in callee or "from_private_bytes" in callee):
                    x25519_key_vars.update(targets)

    findings: list[Finding] = []
    lines = text.splitlines()
    seen: set[tuple] = set()

    def add(algorithm: str, purpose: str, line: int | None, evidence: str,
            library: str | None = None, protocol: str | None = None,
            confidence: str = "CONFIRMED"):
        key = (algorithm, purpose, line, evidence)
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(
            "source", algorithm, purpose, _concern(algorithm, purpose), path,
            line, evidence, confidence=confidence, library=library, protocol=protocol
        ))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        lineno = getattr(node, "lineno", None)
        src = lines[lineno - 1].strip() if lineno and lineno <= len(lines) else "function call"
        raw_func = _expr_name(node.func)
        full_func = resolve(raw_func)
        low = full_func.lower()

        if "ssl.sslcontext" in low:
            add("TLS", "secure transport", lineno, src, library="Python ssl", protocol="TLS")

        if "x25519" in low and ("generate" in low or "exchange" in low or "from_private_bytes" in low):
            add("X25519", "key establishment", lineno, src, library="cryptography")
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "exchange":
            root = _expr_name(node.func.value).split(".")[0]
            if root in x25519_key_vars:
                add("X25519", "key establishment", lineno, src, library="cryptography")

        if "rsa" in low and "generate_private_key" in low:
            add("RSA", "public-key key generation (purpose needs surrounding use)", lineno, src,
                library="cryptography", confidence="OBSERVED_NEEDS_CONTEXT")
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "sign":
            root = _expr_name(node.func.value).split(".")[0]
            if root in rsa_key_vars:
                add("RSA", "digital signature", lineno, src, library="cryptography")

    return findings, None


def scan_config(path: str, data: bytes) -> tuple[list[Finding], str | None]:
    try:
        text = data.decode("utf-8", errors="strict")
    except Exception as e:
        return [], f"Config decode failed: {e}"

    findings: list[Finding] = []
    seen: set[tuple] = set()

    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue

        version_match = re.search(r"\bOpenSSLVersion\s*[=:]\s*([0-9][^\s#;]*)", line, re.I)
        if version_match:
            ver = version_match.group(1)
            key = ("OpenSSL", i)
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    "library", "OpenSSL", "cryptographic implementation/runtime", _concern("OpenSSL", "runtime"),
                    path, i, stripped[:220], library="OpenSSL", version=ver
                ))

        patterns = [
            (re.compile(r"X25519MLKEM768", re.I), "X25519MLKEM768", "key establishment", "TLS"),
            (re.compile(r"\bX25519\b(?!MLKEM)", re.I), "X25519", "key establishment", "TLS"),
            (re.compile(r"\bMLKEM(?:512|768|1024)\b|\bML-KEM-(?:512|768|1024)\b", re.I), "ML-KEM", "key establishment", "TLS"),
            (re.compile(r"\bML-DSA-(?:44|65|87)\b", re.I), "ML-DSA", "digital signature", "TLS certificate/authentication"),
            (re.compile(r"\bTLSv?1\.3\b|\bTLS1_3\b", re.I), "TLS 1.3", "secure transport", "TLS"),
            (re.compile(r"\bRSA(?:-?\d+)?\b", re.I), "RSA", "purpose needs context", None),
        ]
        for rx, alg, purpose, protocol in patterns:
            if rx.search(line):
                key = (alg, i)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    "config", alg, purpose, _concern(alg, purpose), path, i, stripped[:220], protocol=protocol
                ))
    return findings, None


def scan_certificate(path: str, data: bytes) -> tuple[list[Finding], str | None]:
    try:
        cert = x509.load_pem_x509_certificate(data) if b"BEGIN CERTIFICATE" in data else x509.load_der_x509_certificate(data)
    except Exception as e:
        return [], f"Certificate parse failed: {e}"

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        alg, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        # An EC public key alone does not prove whether the key is used as ECDSA or ECDH.
        alg, bits = f"EC ({key.curve.name})", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        alg, bits = "Ed25519", 255
    elif isinstance(key, ed448.Ed448PublicKey):
        alg, bits = "Ed448", 448
    else:
        alg, bits = type(key).__name__, getattr(key, "key_size", None)

    sig = getattr(cert.signature_algorithm_oid, "_name", None) or cert.signature_algorithm_oid.dotted_string
    evidence = (
        f"X.509 subject={cert.subject.rfc4514_string() or 'n/a'}; "
        f"issuer={cert.issuer.rfc4514_string() or 'n/a'}; signature={sig}; "
        f"valid_from={cert.not_valid_before_utc.date()}; valid_to={cert.not_valid_after_utc.date()}"
    )
    return [Finding(
        "certificate", alg, "certificate public key / authentication", _concern(alg, "authentication"),
        path, None, evidence, key_size=bits, protocol="X.509"
    )], None


def scan_manifest(path: str, data: bytes) -> tuple[list[dict], list[dict], str | None]:
    try:
        obj = json.loads(data.decode("utf-8"))
        services = obj.get("services", [])
        contracts = obj.get("contracts", [])
        if not isinstance(services, list) or not isinstance(contracts, list):
            raise ValueError("services and contracts must be arrays")
        return list(services), list(contracts), None
    except Exception as e:
        return [], [], f"Contract manifest parse failed: {e}"


def _artifact_hash(entries: list[ArchiveEntry]) -> str:
    h = hashlib.sha256()
    for entry in sorted(entries, key=lambda e: e.path):
        path = entry.path.encode("utf-8", errors="surrogatepass")
        h.update(len(path).to_bytes(4, "big"))
        h.update(path)
        h.update(len(entry.data).to_bytes(8, "big"))
        h.update(entry.data)
    return h.hexdigest()


def scan_entries(entries: list[ArchiveEntry]) -> dict[str, Any]:
    findings: list[Finding] = []
    errors: list[dict] = []
    services: list[dict] = []
    contracts: list[dict] = []
    supported = 0
    analyzed = 0

    for entry in entries:
        if not entry.supported:
            continue
        supported += 1
        suffix = PurePosixPath(entry.path).suffix.lower()
        if PurePosixPath(entry.path).name == "cipheratlas.contracts.json":
            s, c, err = scan_manifest(entry.path, entry.data)
            services.extend(s)
            contracts.extend(c)
            if err:
                errors.append({"path": entry.path, "error": err})
            else:
                analyzed += 1
            continue

        if suffix == ".py":
            fs, err = scan_python(entry.path, entry.data)
        elif suffix in {".pem", ".crt", ".cer"}:
            fs, err = scan_certificate(entry.path, entry.data)
        elif suffix in {".conf", ".cnf", ".cfg", ".ini", ".json"}:
            fs, err = scan_config(entry.path, entry.data)
        else:
            fs, err = [], None

        findings.extend(fs)
        if err:
            errors.append({"path": entry.path, "error": err})
        else:
            analyzed += 1

    total_files = len(entries)
    unsupported = sum(1 for e in entries if not e.supported)
    coverage = round((analyzed / total_files * 100), 1) if total_files else 0.0
    return {
        "findings": [f.to_dict() for f in findings],
        "services": services,
        "contracts": contracts,
        "coverage": {
            "total_files": total_files,
            "supported_files": supported,
            "analyzed_files": analyzed,
            "unsupported_files": unsupported,
            "parse_failures": len(errors),
            "percent": coverage,
            "status": "COMPLETE" if total_files and analyzed == total_files else "SCAN_INCOMPLETE",
        },
        "errors": errors,
        "artifact_sha256": _artifact_hash(entries),
    }
