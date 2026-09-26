"""Synthetic enterprise estate generator with hidden ground truth.

Independence rule: this module must not import anything from selectors.py.
Its RNG is seeded separately from the selectors' RNG.

Library capability truths follow public facts as understood on 2026-09-26
(VERIFY before reuse). Upgrade availability and app-level checks are sampled.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .model import Contract, Estate, Knowledge, Node, app_fact, lib_fact, upg_fact

# stack -> (sig, kex, trans) truth, and sampling weight
STACKS: dict[str, tuple[tuple[bool, bool, bool] | None, float]] = {
    "openssl-1.1.1": ((False, False, False), 0.10),
    "openssl-3.0": ((False, False, False), 0.20),
    "openssl-3.5": ((True, True, True), 0.20),
    "go-1.24": ((False, True, False), 0.10),
    "go-1.27": ((True, True, True), 0.08),
    "java-bc-1.70": ((False, False, False), 0.10),
    "java-bc-1.80": ((True, True, True), 0.10),
    "node-22": ((False, False, False), 0.07),
    "vendor-appliance": (None, 0.05),  # truth sampled per estate
}


@dataclass
class Scenario:
    estate: Estate
    truth: dict[str, bool]
    initial: Knowledge


def generate(seed: int, n_services: int = 24, n_clients: int = 8, twin_mode: bool = True) -> Scenario:
    rng = random.Random(seed)
    names = list(STACKS)
    weights = [STACKS[s][1] for s in names]
    nodes: dict[str, Node] = {}

    def add(prefix: str, i: int, client: bool) -> str:
        nid = f"{prefix}{i}"
        nodes[nid] = Node(
            id=nid,
            stack=rng.choices(names, weights)[0],
            crit=rng.randint(1, 5),
            upgrade_cost=rng.randint(1, 10),
            is_client=client,
        )
        return nid

    services = [add("svc", i, False) for i in range(n_services)]
    clients = [add("cli", i, True) for i in range(n_clients)]

    contracts: dict[str, Contract] = {}

    def link(p: str, c: str, purpose: str) -> None:
        cid = f"k{len(contracts)}"
        contracts[cid] = Contract(cid, p, c, purpose, rng.randint(1, 5))  # type: ignore[arg-type]

    # hub 1: auth service signs tokens for many consumers
    auth = services[0]
    for c in rng.sample(services[1:] + clients, k=max(2, (n_services + n_clients) // 3)):
        link(auth, c, "sig")
    # hub 2: internal CA signs certs consumed (verified) by many
    ca = services[1]
    for c in rng.sample(services[2:], k=max(2, n_services // 3)):
        link(ca, c, "sig")
    # a few other signers with 1-3 consumers
    for p in rng.sample(services[2:], k=max(1, n_services // 8)):
        for c in rng.sample([s for s in services + clients if s != p], k=rng.randint(1, 3)):
            link(p, c, "sig")
    # TLS key establishment edges (server = producer, client = consumer)
    for _ in range(n_services + n_clients):
        p = rng.choice(services)
        c = rng.choice([s for s in services + clients if s != p])
        link(p, c, "kex")

    estate = Estate(nodes, contracts, twin_mode=twin_mode)
    vendor_truth = tuple(rng.random() < 0.3 for _ in range(3))
    truth: dict[str, bool] = {}
    for f in sorted(estate.all_facts()):  # sorted: set order depends on PYTHONHASHSEED
        kind, rest = f.split(":", 1)
        if kind in ("lib", "nlib"):
            who, cap = rest.rsplit(":", 1)
            stack = nodes[who].stack if kind == "nlib" else who
            t = STACKS[stack][0] or vendor_truth
            truth[f] = t[{"sig": 0, "kex": 1, "trans": 2}[cap]]
        elif kind == "app":
            truth[f] = rng.random() < 0.85
        else:
            n = nodes[rest]
            prob = 0.3 if n.stack == "vendor-appliance" else (0.5 if n.is_client else 0.8)
            truth[f] = rng.random() < prob

    known: dict[str, bool | None] = {f: None for f in truth}
    for f, v in truth.items():
        # some app facts are confirmed by static config; some upgrade facts by vendor data
        if f.startswith("app:") and v and rng.random() < 0.25:
            known[f] = True
        if f.startswith("upg:") and rng.random() < 0.10:
            known[f] = v
    return Scenario(estate, truth, Knowledge(known))


__all__ = ["Scenario", "generate", "STACKS", "lib_fact", "app_fact", "upg_fact"]
