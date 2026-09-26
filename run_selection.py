"""Gate 4: run the pre-registered test-selection competition.

Usage: python -m phase0.run_selection --seeds 40 --out phase0/results/selection.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
from dataclasses import asdict
from multiprocessing import Pool

from .sim.engine import COST_MODELS, run
from .sim.generator import generate
from .sim.selectors import STRATEGIES


def _job(args: tuple[int, str]) -> list[dict]:
    seed, cm = args
    out = []
    for name, sel in STRATEGIES.items():
        scen = generate(seed)  # fresh scenario per strategy: no shared solver cache
        out.append(asdict(run(scen, name, sel, cm, seed)))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=40)
    ap.add_argument("--out", default="phase0/results/selection.jsonl")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    jobs = [(s, cm) for cm in COST_MODELS for s in range(a.seeds)]
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    meta = {"commit": commit, "python": platform.python_version(), "machine": platform.machine(),
            "cpus": os.cpu_count(), "seeds": a.seeds}
    with Pool(a.workers) as pool, open(a.out, "w") as fh:
        fh.write(json.dumps({"meta": meta}) + "\n")
        for rows in pool.imap_unordered(_job, jobs):
            for r in rows:
                fh.write(json.dumps(r) + "\n")
    print("wrote", a.out)


if __name__ == "__main__":
    main()
