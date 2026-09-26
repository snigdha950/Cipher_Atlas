"""Core data model for the Phase 0 migration-planning experiment.

Facts are the only uncertain things. A fact is a yes/no statement such as
"stack openssl-3.5 can verify ML-DSA signatures" or "consumer svc-7 accepts
a token of PQ size". The hidden truth lives in a separate dict owned by the
evaluator; planners and selectors only ever see a Knowledge object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Purpose = Literal["sig", "kex"]
FactKind = Literal["lib", "app", "vendor"]


@dataclass(frozen=True)
class Node:
    id: str
    stack: str
    crit: int  # 1..5
    upgrade_cost: int  # 1..10
    is_client: bool = False


@dataclass(frozen=True)
class Contract:
    id: str
    producer: str
    consumer: str
    purpose: Purpose
    crit: int  # 1..5


@dataclass(frozen=True)
class Fact:
    id: str
    kind: FactKind


def lib_fact(stack: str, capability: str) -> str:
    """capability is 'sig', 'kex' or 'trans' (transition/dual-key support)."""
    return f"lib:{stack}:{capability}"


def app_fact(node: str, purpose: Purpose) -> str:
    return f"app:{node}:{purpose}"


def upg_fact(node: str) -> str:
    return f"upg:{node}"


def fact_kind(fid: str) -> FactKind:
    prefix = fid.split(":", 1)[0]
    # "nlib" = a node's library capability tested per node on staging (no twins): app-level cost
    return {"lib": "lib", "nlib": "app", "app": "app", "upg": "vendor"}[prefix]  # type: ignore[return-value]


@dataclass
class Estate:
    nodes: dict[str, Node]
    contracts: dict[str, Contract]
    twin_mode: bool = True  # False = ablation: no library twins, capability tested per node

    def cap_fact(self, node: str, capability: str) -> str:
        if self.twin_mode:
            return lib_fact(self.nodes[node].stack, capability)
        return f"nlib:{node}:{capability}"

    def facts_for_contract(self, c: Contract) -> set[str]:
        p, q = self.nodes[c.producer], self.nodes[c.consumer]
        fs = {
            self.cap_fact(p.id, c.purpose),
            self.cap_fact(q.id, c.purpose),
            app_fact(q.id, c.purpose),
            upg_fact(p.id),
            upg_fact(q.id),
        }
        if c.purpose == "sig":
            fs.add(self.cap_fact(p.id, "trans"))
        return fs

    def all_facts(self) -> set[str]:
        out: set[str] = set()
        for c in self.contracts.values():
            out |= self.facts_for_contract(c)
        return out


@dataclass
class Knowledge:
    """What the system currently knows. None = UNKNOWN."""

    values: dict[str, bool | None] = field(default_factory=dict)

    def get(self, fid: str) -> bool | None:
        return self.values.get(fid)

    def unknowns(self) -> set[str]:
        return {f for f, v in self.values.items() if v is None}

    def valuation(self, default: bool, overrides: dict[str, bool] | None = None) -> dict[str, bool]:
        val = {f: (default if v is None else v) for f, v in self.values.items()}
        if overrides:
            val.update(overrides)
        return val
