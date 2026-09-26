"""EXPLORATORY (post-hoc, not pre-registered): how much does the library-twin evidence model save?

twin_mode=True : a library capability fact is shared by every node on that stack and costs a cheap twin probe.
twin_mode=False: each node's capability must be tested on its own staging environment (app-level cost).
Same seeds, same generator, same strategies, same certification rule.
"""

from __future__ import annotations

import json
import statistics as st
import sys
from dataclasses import asdict
from multiprocessing import Pool

from .analyze_selection import boot_ci
from .sim.engine import run
from .sim.generator import generate
from .sim.selectors import STRATEGIES

STRATS = ["criticality", "fanin", "decisive", "test_all"]


def _job(args):
    seed, cm, twin = args
    return [dict(asdict(run(generate(seed, twin_mode=twin), s, STRATEGIES[s], cm, seed)), twin_mode=twin) for s in STRATS]


def main(out: str, seeds: int = 40) -> None:
    jobs = [(s, cm, t) for cm in ("two_tier", "steep") for t in (True, False) for s in range(seeds)]
    rows = []
    with Pool(2) as p:
        for r in p.imap_unordered(_job, jobs):
            rows.extend(r)
    json.dump(rows, open(out, "w"), indent=0)
    idx = {(r["cost_model"], r["strategy"], r["twin_mode"], r["seed"]): r for r in rows}
    for cm in ("two_tier", "steep"):
        for s in STRATS:
            a = [idx[(cm, s, True, x)]["cost_to_certify"] for x in range(seeds)]
            b = [idx[(cm, s, False, x)]["cost_to_certify"] for x in range(seeds)]
            d = [bb - aa for aa, bb in zip(a, b, strict=True)]
            lo, hi = boot_ci(d)
            print(f"{cm:9} {s:12} twin={st.fmean(a):8.1f} no_twin={st.fmean(b):8.1f} "
                  f"saving={100 * st.fmean(d) / st.fmean(b):5.1f}% CI95(diff)=[{lo:.0f},{hi:.0f}]")


if __name__ == "__main__":
    main(sys.argv[1])
