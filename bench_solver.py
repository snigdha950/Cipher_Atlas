"""Gate 3: solver scaling benchmark.

Usage: python -m phase0.bench_solver --out phase0/results/solver_bench.json
"""

from __future__ import annotations

import argparse
import json
import random
import time

from .sim.engine import Context
from .sim.generator import generate
from .sim.model import Knowledge
from .sim.selectors import decisive
from .sim.solver import components

SIZES = {100: (50, 10), 1000: (500, 60), 10000: (5000, 400)}


def bench(target: int, seed: int, decisive_budget_s: float) -> dict:
    ns, nc = SIZES[target]
    scen = generate(seed, n_services=ns, n_clients=nc)
    t = time.perf_counter()
    comps = components(scen.estate)
    t_comp = time.perf_counter() - t
    know = Knowledge(dict(scen.initial.values))
    ctx = Context(scen, know, comps, {"lib": 1, "app": 10, "vendor": 50}, random.Random(0))
    t = time.perf_counter()
    ctx.refresh()  # optimistic + pessimistic solve of every component
    t_refresh = time.perf_counter() - t
    sizes = sorted((len(c.contracts) for c in comps), reverse=True)
    res = {
        "target_contracts": target,
        "seed": seed,
        "contracts": len(scen.estate.contracts),
        "unknown_facts": len(know.unknowns()),
        "components": len(comps),
        "largest_component": sizes[0],
        "t_components_s": round(t_comp, 4),
        "t_opt_plus_pes_solve_s": round(t_refresh, 4),
        "assumptions": len(ctx.assumptions),
    }
    # one decisive-selection pass, measured with a wall-clock budget
    t = time.perf_counter()
    if len(ctx.assumptions) * 2 * max(t_refresh / 2, 1e-3) <= decisive_budget_s:
        decisive(ctx)
        res["t_decisive_pass_s"] = round(time.perf_counter() - t, 4)
    else:
        res["t_decisive_pass_s"] = None
        res["decisive_note"] = (
            f"skipped: estimated {len(ctx.assumptions) * t_refresh:.0f}s > budget {decisive_budget_s}s"
        )
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="phase0/results/solver_bench.json")
    ap.add_argument("--budget", type=float, default=300.0)
    a = ap.parse_args()
    rows = []
    for t in SIZES:
        for s in range(3):
            rows.append(bench(t, s, a.budget))
            print(rows[-1], flush=True)
            with open(a.out, "w") as fh:
                json.dump(rows, fh, indent=1)


if __name__ == "__main__":
    main()
