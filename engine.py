"""Test-until-certified loop, identical for every selection strategy."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Callable

from .generator import Scenario
from .model import Knowledge, fact_kind
from .solver import Component, Plan, components, plan_feasible, plan_value

COST_MODELS: dict[str, dict[str, int]] = {
    "uniform": {"lib": 1, "app": 1, "vendor": 1},
    "two_tier": {"lib": 1, "app": 10, "vendor": 50},
    "steep": {"lib": 1, "app": 30, "vendor": 200},
}


@dataclass
class Context:
    scen: Scenario
    know: Knowledge
    comps: list[Component]
    cost: dict[str, int]
    rng: random.Random
    opt: dict[int, Plan] = field(default_factory=dict)
    pes: dict[int, Plan] = field(default_factory=dict)
    gap: list[int] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)  # fact -> #plan contracts relying on it
    assumptions: set[str] = field(default_factory=set)

    def fact_cost(self, f: str) -> int:
        return self.cost[fact_kind(f)]

    def refresh(self) -> None:
        vo = self.know.valuation(True)
        vp = self.know.valuation(False)
        self.opt = {i: c.solve(vo) for i, c in enumerate(self.comps)}
        self.pes = {i: c.solve(vp) for i, c in enumerate(self.comps)}
        self.gap = [i for i in self.opt if self.opt[i].objective > self.pes[i].objective]
        unknown = self.know.unknowns()
        self.usage = {}
        for i in self.gap:
            comp, plan = self.comps[i], self.opt[i]
            for c in comp.contracts:
                if c.id not in plan.migrated:
                    continue
                single = Plan(0, frozenset({c.id}), plan.upgraded, "X")
                for f in comp.facts_used(single) & unknown:
                    self.usage[f] = self.usage.get(f, 0) + 1
            for f in comp.facts_used(plan) & unknown:
                self.usage.setdefault(f, 1)
        self.assumptions = set(self.usage)


Selector = Callable[[Context], str]


@dataclass
class RunResult:
    strategy: str
    seed: int
    cost_model: str
    cost_to_certify: int
    probes_to_certify: int
    cost_to_first_correct: int | None
    wrong_intermediate_plans: int
    blockers_found: int
    unknowns_initial: int
    final_objective: int
    true_objective: int
    final_correct: bool
    solves: int
    seconds: float


def _true_optimum(scen: Scenario, comps: list[Component]) -> tuple[int, dict[int, Plan]]:
    plans = {i: c.solve(scen.truth) for i, c in enumerate(comps)}
    return sum(p.objective for p in plans.values()), plans


def run(scen: Scenario, selector_name: str, selector: Selector, cost_model: str, seed: int) -> RunResult:
    t0 = time.perf_counter()
    comps = components(scen.estate)
    know = Knowledge(dict(scen.initial.values))
    ctx = Context(scen, know, comps, COST_MODELS[cost_model], random.Random(seed * 7919 + 1))
    true_obj, _ = _true_optimum(scen, comps)
    n_unknown0 = len(know.unknowns())

    cost = probes = wrong = blockers = 0
    first_correct: int | None = None

    if selector_name == "test_all":
        for f in sorted(know.unknowns()):
            cost += ctx.fact_cost(f)
            probes += 1
            blockers += int(not scen.truth[f])
            know.values[f] = scen.truth[f]
        ctx.refresh()
        first_correct = cost
    else:
        while True:
            ctx.refresh()
            opt_ok = all(plan_feasible(comps[i], p, scen.truth) for i, p in ctx.opt.items())
            opt_val = sum(plan_value(comps[i], p) for i, p in ctx.opt.items())
            if opt_ok and opt_val == true_obj and first_correct is None:
                first_correct = cost
            if not ctx.gap:
                break
            if not opt_ok:
                wrong += 1
            f = selector(ctx)
            assert know.values[f] is None, f"selector {selector_name} chose known fact {f}"
            cost += ctx.fact_cost(f)
            probes += 1
            blockers += int(not scen.truth[f])
            know.values[f] = scen.truth[f]

    final = sum(p.objective for p in ctx.pes.values())
    final_ok = final == true_obj and all(
        plan_feasible(comps[i], p, scen.truth) for i, p in ctx.pes.items()
    )
    return RunResult(
        strategy=selector_name,
        seed=seed,
        cost_model=cost_model,
        cost_to_certify=cost,
        probes_to_certify=probes,
        cost_to_first_correct=first_correct,
        wrong_intermediate_plans=wrong,
        blockers_found=blockers,
        unknowns_initial=n_unknown0,
        final_objective=final,
        true_objective=true_obj,
        final_correct=final_ok,
        solves=sum(c.solves for c in comps),
        seconds=round(time.perf_counter() - t0, 4),
    )
