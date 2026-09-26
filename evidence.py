from __future__ import annotations

import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
PHASE0 = BASE / "research" / "phase0" / "results" / "tls_probes.json"


def _load() -> dict:
    return json.loads(PHASE0.read_text())


def profiles() -> list[dict]:
    d = _load()
    out = []
    for key, v in d["twins"].items():
        out.append({
            "id": key,
            "display": v["version"],
            "ml_kem": v["ml_kem"],
            "ml_dsa": v["ml_dsa"],
            "slh_dsa": v["slh_dsa"],
            "source": "Measured Phase 0 crypto-stack evidence",
            "scope": "Exact tested library version; app-specific configuration may require a direct probe",
        })
    return out


def measured_probe(client: str, server_config: str = "hybrid_with_classical_fallback", cert_alg: str = "ecdsa-p256") -> dict | None:
    d = _load()
    for h in d["handshakes"]:
        if h.get("client") == client and h.get("server_config") == server_config and h.get("cert_alg") == cert_alg:
            record = dict(h)
            record["mode"] = "RECORDED_MEASURED_RUN"
            record["source_file"] = "research/phase0/results/tls_probes.json"
            record["source_sha256"] = hashlib.sha256(PHASE0.read_bytes()).hexdigest()
            record["scope"] = "Measured in Phase 0 Linux sandbox; not a claim about every application using this library."
            return record
    return None
