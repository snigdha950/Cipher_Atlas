"""Summarise the selection experiment with paired bootstrap CIs (pre-registered analysis)."""

from __future__ import annotations

import json
import random
import statistics as st
import sys
from collections import defaultdict


def boot_ci(diffs: list[float], n: int = 10000, seed: int = 0) -> tuple[float, float]:
    rng = random.Random(seed)
    means = sorted(st.fmean(rng.choices(diffs, k=len(diffs))) for _ in range(n))
    return means[int(0.025 * n)], means[int(0.975 * n)]


def main(path: str) -> dict:
    lines = [json.loads(x) for x in open(path)]
    meta, rows = lines[0]["meta"], lines[1:]
    by = defaultdict(dict)  # (cm, strategy) -> seed -> row
    for r in rows:
        by[(r["cost_model"], r["strategy"])][r["seed"]] = r
    out: dict = {"meta": meta, "summary": {}, "h1": {}, "checks": {}}
    out["checks"]["all_final_plans_correct"] = all(r["final_correct"] for r in rows)
    cms = sorted({r["cost_model"] for r in rows})
    strategies = sorted({r["strategy"] for r in rows})
    for cm in cms:
        out["summary"][cm] = {}
        for s in strategies:
            rs = list(by[(cm, s)].values())
            fc = [r["cost_to_first_correct"] for r in rs if r["cost_to_first_correct"] is not None]
            out["summary"][cm][s] = {
                "n": len(rs),
                "mean_cost_to_certify": round(st.fmean(r["cost_to_certify"] for r in rs), 1),
                "mean_probes": round(st.fmean(r["probes_to_certify"] for r in rs), 1),
                "mean_cost_to_first_correct_plan": round(st.fmean(fc), 1) if fc else None,
                "mean_wrong_intermediate_plans": round(st.fmean(r["wrong_intermediate_plans"] for r in rs), 2),
                "mean_seconds": round(st.fmean(r["seconds"] for r in rs), 3),
            }
        # paired comparisons against decisive
        for base in ("fanin", "criticality", "evoi", "random"):
            seeds = sorted(set(by[(cm, "decisive")]) & set(by[(cm, base)]))
            d = [by[(cm, base)][x]["cost_to_certify"] - by[(cm, "decisive")][x]["cost_to_certify"] for x in seeds]
            dfc = [
                (by[(cm, base)][x]["cost_to_first_correct"] or 0) - (by[(cm, "decisive")][x]["cost_to_first_correct"] or 0)
                for x in seeds
            ]
            lo, hi = boot_ci(d)
            lo2, hi2 = boot_ci(dfc)
            base_mean = st.fmean(by[(cm, base)][x]["cost_to_certify"] for x in seeds)
            out["h1"][f"{cm}:{base}-decisive"] = {
                "mean_diff_certify": round(st.fmean(d), 1),
                "ci95_certify": [round(lo, 1), round(hi, 1)],
                "rel_reduction_certify_pct": round(100 * st.fmean(d) / base_mean, 1),
                "mean_diff_first_correct": round(st.fmean(dfc), 1),
                "ci95_first_correct": [round(lo2, 1), round(hi2, 1)],
            }
    return out


if __name__ == "__main__":
    res = main(sys.argv[1])
    json.dump(res, open(sys.argv[2], "w"), indent=1)
    for cm, d in res["summary"].items():
        print(f"\n== {cm}")
        print(f'{"strategy":14} {"certify$":>9} {"probes":>7} {"firstOK$":>9} {"wrong":>6} {"sec":>6}')
        for s, v in sorted(d.items(), key=lambda kv: kv[1]["mean_cost_to_certify"]):
            print(f'{s:14} {v["mean_cost_to_certify"]:9} {v["mean_probes"]:7} {str(v["mean_cost_to_first_correct_plan"]):>9} '
                  f'{v["mean_wrong_intermediate_plans"]:6} {v["mean_seconds"]:6}')
    print()
    for k, v in res["h1"].items():
        print(k, v)
    print(res["checks"])
