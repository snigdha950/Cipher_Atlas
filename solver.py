"""CP-SAT migration planner.

Decision variables per connected component of the contract graph:
  mig[k]  contract k is migrated to its PQ mechanism in this plan
  upg[n]  node n is upgraded to a PQ-capable stack (only if its upgrade fact is true)

Constraints (for a fully specified valuation of facts):
  mig[k] -> producer and consumer can do the purpose (native library support or upgraded)
  mig[k] -> consumer passes its app-level check for that purpose (size limits, middlebox, pinning)
  signature contracts that share a producer key must all migrate together unless the
  producer supports a transition mechanism (dual keys) natively or after upgrade.

Objective: maximise sum(W * crit * mig) - sum(upgrade_cost * upg).
Ordering of steps (upgrades before migrations) is derived afterwards; it is not optimised.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx
from ortools.sat.python import cp_model

from .model import Contract, Estate, app_fact, upg_fact

W = 1000


@dataclass(frozen=True)
class Plan:
    objective: int
    migrated: frozenset[str]
    upgraded: frozenset[str]
    status: str  # OPTIMAL / FEASIBLE / TIMEOUT


class Component:
    def __init__(self, estate: Estate, contract_ids: list[str]):
        self.estate = estate
        self.contracts: list[Contract] = [estate.contracts[c] for c in sorted(contract_ids)]
        nodes: set[str] = set()
        facts: set[str] = set()
        for c in self.contracts:
            nodes |= {c.producer, c.consumer}
            facts |= estate.facts_for_contract(c)
        self.node_ids = sorted(nodes)
        self.facts = sorted(facts)
        # signature contracts sharing a producer key (precomputed: avoids O(k^2) scans)
        self.sig_groups: dict[str, list[str]] = {}
        for c in self.contracts:
            if c.purpose == "sig":
                self.sig_groups.setdefault(c.producer, []).append(c.id)
        self._cache: dict[tuple[bool, ...], Plan] = {}
        self.solves = 0

    def solve(self, val: dict[str, bool], time_limit_s: float = 10.0) -> Plan:
        key = tuple(val[f] for f in self.facts)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        plan = self._solve_uncached(val, time_limit_s)
        self._cache[key] = plan
        return plan

    def _solve_uncached(self, val: dict[str, bool], time_limit_s: float) -> Plan:
        self.solves += 1
        est = self.estate
        m = cp_model.CpModel()
        upg = {}
        for n in self.node_ids:
            v = m.NewBoolVar(f"upg_{n}")
            if not val[upg_fact(n)]:
                m.Add(v == 0)
            upg[n] = v
        mig = {c.id: m.NewBoolVar(f"mig_{c.id}") for c in self.contracts}

        for c in self.contracts:
            for n in (c.producer, c.consumer):
                if not val[est.cap_fact(n, c.purpose)]:
                    m.AddImplication(mig[c.id], upg[n])
            if not val[app_fact(c.consumer, c.purpose)]:
                m.Add(mig[c.id] == 0)

        for p, ks in self.sig_groups.items():
            if len(ks) < 2 or val[est.cap_fact(p, "trans")]:
                continue
            first = ks[0]
            for k in ks[1:]:
                m.Add(mig[k] == mig[first]).OnlyEnforceIf(upg[p].Not())

        m.Maximize(
            sum(W * c.crit * mig[c.id] for c in self.contracts)
            - sum(est.nodes[n].upgrade_cost * upg[n] for n in self.node_ids)
        )
        s = cp_model.CpSolver()
        s.parameters.max_time_in_seconds = time_limit_s
        s.parameters.num_workers = 1  # deterministic
        st = s.Solve(m)
        if st == cp_model.OPTIMAL:
            status = "OPTIMAL"
        elif st == cp_model.FEASIBLE:
            status = "FEASIBLE"
        else:
            status = "TIMEOUT"
        if st not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            return Plan(0, frozenset(), frozenset(), status)
        return Plan(
            objective=int(round(s.ObjectiveValue())),
            migrated=frozenset(k for k, v in mig.items() if s.Value(v)),
            upgraded=frozenset(n for n, v in upg.items() if s.Value(v)),
            status=status,
        )

    def facts_used(self, plan: Plan) -> set[str]:
        """Facts whose truth the plan relies on (only positive reliance matters)."""
        est = self.estate
        used: set[str] = set()
        mig_by_prod: dict[str, set[str]] = {}
        for c in self.contracts:
            if c.id not in plan.migrated:
                if c.purpose == "sig":
                    mig_by_prod.setdefault(c.producer, set())
                continue
            used.add(app_fact(c.consumer, c.purpose))
            for n in (c.producer, c.consumer):
                if n in plan.upgraded:
                    used.add(upg_fact(n))
                else:
                    used.add(est.cap_fact(n, c.purpose))
            if c.purpose == "sig":
                mig_by_prod.setdefault(c.producer, set()).add(c.id)
        # partial migration of a shared key relies on transition support
        for p, migs in mig_by_prod.items():
            group = self.sig_groups[p]
            if 0 < len(migs) < len(group) and p not in plan.upgraded:
                used.add(est.cap_fact(p, "trans"))
        for n in plan.upgraded:
            used.add(upg_fact(n))
        return used


def plan_feasible(comp: Component, plan: Plan, val: dict[str, bool]) -> bool:
    """Check a plan against a full valuation (used by the evaluator with the hidden truth)."""
    est = comp.estate
    for n in plan.upgraded:
        if not val[upg_fact(n)]:
            return False
    for c in comp.contracts:
        if c.id not in plan.migrated:
            continue
        if not val[app_fact(c.consumer, c.purpose)]:
            return False
        for n in (c.producer, c.consumer):
            if n not in plan.upgraded and not val[est.cap_fact(n, c.purpose)]:
                return False
    for p, group in comp.sig_groups.items():
        k = sum(1 for g in group if g in plan.migrated)
        if 0 < k < len(group) and p not in plan.upgraded and not val[
            est.cap_fact(p, "trans")
        ]:
            return False
    return True


def plan_value(comp: Component, plan: Plan) -> int:
    est = comp.estate
    return sum(W * est.contracts[k].crit for k in plan.migrated) - sum(
        est.nodes[n].upgrade_cost for n in plan.upgraded
    )


def components(estate: Estate) -> list[Component]:
    g = nx.Graph()
    for c in estate.contracts.values():
        g.add_edge(("n", c.producer), ("c", c.id))
        g.add_edge(("n", c.consumer), ("c", c.id))
    comps = []
    for cc in nx.connected_components(g):
        ids = [x[1] for x in cc if x[0] == "c"]
        if ids:
            comps.append(Component(estate, ids))
    comps.sort(key=lambda c: c.contracts[0].id)
    return comps
