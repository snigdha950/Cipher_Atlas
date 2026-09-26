from __future__ import annotations

import json
import zipfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .evidence import profiles
from .planner import migration_decision
from .probes import local_probe_capability, run_probe
from .scanner import scan_entries
from .security import ArchiveEntry, UnsafeArchive, read_zip_safely

BASE = Path(__file__).resolve().parents[1]
FRONTEND = BASE / "frontend"
SAMPLE = BASE / "sample_project"

app = FastAPI(title="CipherAtlas MVP", version="1.1.0")
app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


class ProbeRequest(BaseModel):
    client: str
    server_config: str = "hybrid_with_classical_fallback"


def sample_entries() -> list[ArchiveEntry]:
    allowed = {".py", ".conf", ".cnf", ".cfg", ".ini", ".json", ".pem", ".crt", ".cer"}
    entries = []
    for p in SAMPLE.rglob("*"):
        if p.is_file():
            suffix = p.suffix.lower()
            entries.append(ArchiveEntry(
                str(p.relative_to(SAMPLE)).replace("\\", "/"), p.read_bytes(), suffix in allowed
            ))
    return entries


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "mode": "offline-ready",
        "version": "1.1.0",
        "live_probe": local_probe_capability(),
    }


@app.get("/api/profiles")
def stack_profiles():
    return {"profiles": profiles()}


@app.get("/api/sample-scan")
def sample_scan():
    return scan_entries(sample_entries())


@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    blob = await file.read()
    if len(blob) > 15 * 1024 * 1024:
        raise HTTPException(413, "Upload too large")
    try:
        if (file.filename or "").lower().endswith(".zip"):
            entries = read_zip_safely(blob)
        else:
            name = file.filename or "upload.bin"
            suffix = Path(name).suffix.lower()
            entries = [ArchiveEntry(
                name, blob,
                suffix in {".py", ".conf", ".cnf", ".cfg", ".ini", ".json", ".pem", ".crt", ".cer"}
            )]
        return scan_entries(entries)
    except (UnsafeArchive, zipfile.BadZipFile) as e:
        raise HTTPException(400, str(e)) from e


@app.post("/api/probe")
def probe(req: ProbeRequest):
    evidence = run_probe(req.client, req.server_config)
    decision = migration_decision(evidence)
    return {"evidence": evidence, "decision": decision}


@app.get("/api/research-summary")
def research_summary():
    p = BASE / "research" / "phase0" / "results" / "selection_summary.json"
    twins = BASE / "research" / "phase0" / "results" / "twin_ablation.json"
    solver = BASE / "research" / "phase0" / "results" / "solver_bench.json"
    return {
        "selection_summary": json.loads(p.read_text()) if p.exists() else {},
        "solver_bench": json.loads(solver.read_text()) if solver.exists() else {},
        "note": "Phase 0 measured results are bundled for evidence/replay. They are not claimed to generalize to every production environment.",
        "twin_ablation_available": twins.exists(),
    }
