"""Test-selection strategies. Every strategy picks from ctx.assumptions
(unknown facts the current optimistic plan relies on), so they differ only in ORDER."""

from __future__ import annotations

from .engine import Context, Selector
from .model import fact_kind

# prior failure probabilities per fact kind (roughly matching the generator's rates)
PRIOR_FAIL = {"lib": 0.55, "app": 0.15, "vendor": 0.35}


def _pick(ctx: Context, score: dict[str, float]) -> str:
    # highest score, then cheapest, then id (deterministic)
    return min(score, key=lambda f: (-score[f], ctx.fact_cost(f), f))


def random_sel(ctx: Context) -> str:
    return ctx.rng.choice(sorted(ctx.assumptions))


def criticality(ctx: Context) -> str:
    est = ctx.scen.estate
    score: dict[str, float] = {}
    for f in ctx.assumptions:
        score[f] = sum(c.crit for c in est.contracts.values() if f in est.facts_for_contract(c))
    return _pick(ctx, score)


def centrality(ctx: Context) -> str:
    est = ctx.scen.estate
    deg: dict[str, int] = {}
    for c in est.contracts.values():
        deg[c.producer] = deg.get(c.producer, 0) + 1
        deg[c.consumer] = deg.get(c.consumer, 0) + 1
    score: dict[str, float] = {}
    for f in ctx.assumptions:
        kind, rest = f.split(":", 1)
        if kind == "lib":  # shared by every node on that stack
            stack = rest.rsplit(":", 1)[0]
            score[f] = sum(d for n, d in deg.items() if est.nodes[n].stack == stack)
        else:
            node = rest.split(":", 1)[0]
            score[f] = deg.get(node, 0)
    return _pick(ctx, score)


def fanin(ctx: Context) -> str:
    return _pick(ctx, {f: float(ctx.usage[f]) for f in ctx.assumptions})


# DEVIATION from pre-registration: the pre-registered misprior (all probabilities x 0.3)
# scales every score equally and cannot change the ranking. We use an inverted prior instead.
MISPRIOR_FAIL = {"lib": 0.15, "app": 0.55, "vendor": 0.10}


def make_evoi(prior: dict[str, float]) -> Selector:
    def evoi(ctx: Context) -> str:
        score = {
            f: prior[fact_kind(f)] * ctx.usage[f] / ctx.fact_cost(f) for f in ctx.assumptions
        }
        return _pick(ctx, score)

    return evoi


def decisive(ctx: Context) -> str:
    """Two-sided solver sensitivity.

    A fact is decisive if learning it FALSE lowers the optimistic objective, or learning it
    TRUE raises the pessimistic objective, of its component. Either answer then narrows the
    optimistic/pessimistic gap. Among decisive facts: cheapest first, then largest effect.
    Changing only WHICH equally-good plan is chosen does not count (spurious decisiveness).
    """
    best: tuple[int, float, str] | None = None
    for i in ctx.gap:
        comp = ctx.comps[i]
        comp_facts = set(comp.facts)
        cand = [f for f in ctx.assumptions if f in comp_facts]
        for f in cand:
            o = comp.solve(ctx.know.valuation(True, {f: False})).objective
            p = comp.solve(ctx.know.valuation(False, {f: True})).objective
            effect = max(ctx.opt[i].objective - o, p - ctx.pes[i].objective)
            if effect <= 0:
                continue
            key = (ctx.fact_cost(f), -effect, f)
            if best is None or key < (best[0], -best[1], best[2]):
                best = (ctx.fact_cost(f), float(effect), f)
    if best is not None:
        return best[2]
    return fanin(ctx)  # joint-only uncertainty: no single fact is decisive


def oracle(ctx: Context) -> str:
    """Knows the hidden truth. Tests the false facts the plan relies on (cheapest first),
    then falls back to decisive. A heuristic lower bound, not a proven minimum."""
    false_used = [f for f in ctx.assumptions if not ctx.scen.truth[f]]
    if false_used:
        return min(false_used, key=lambda f: (ctx.fact_cost(f), f))
    return decisive(ctx)


STRATEGIES: dict[str, Selector] = {
    "random": random_sel,
    "criticality": criticality,
    "centrality": centrality,
    "fanin": fanin,
    "evoi": make_evoi(PRIOR_FAIL),
    "evoi_misprior": make_evoi(MISPRIOR_FAIL),
    "decisive": decisive,
    "oracle": oracle,
    "test_all": fanin,  # placeholder; engine handles test_all specially
}
