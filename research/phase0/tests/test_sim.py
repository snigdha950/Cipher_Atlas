from phase0.sim.engine import Context, run
from phase0.sim.generator import generate
from phase0.sim.model import Contract, Estate, Knowledge, Node, app_fact, lib_fact, upg_fact
from phase0.sim.selectors import STRATEGIES, decisive
from phase0.sim.solver import W, components


def _hub_estate() -> Estate:
    nodes = {
        "auth": Node("auth", "A", 3, 5),
        "gw": Node("gw", "B", 3, 5),
        "old": Node("old", "C", 3, 5, is_client=True),
    }
    contracts = {
        "k0": Contract("k0", "auth", "gw", "sig", 3),
        "k1": Contract("k1", "auth", "old", "sig", 1),
    }
    return Estate(nodes, contracts)


def _val(trans: bool, old_ok: bool) -> dict[str, bool]:
    v = {f: True for f in _hub_estate().all_facts()}
    v[upg_fact("auth")] = False
    v[upg_fact("old")] = False
    v[lib_fact("C", "sig")] = old_ok
    v[lib_fact("A", "trans")] = trans
    return v


def test_shared_key_without_transition_blocks_everyone():
    (comp,) = components(_hub_estate())
    plan = comp.solve(_val(trans=False, old_ok=False))
    assert plan.migrated == frozenset()  # one incapable consumer blocks the whole key


def test_transition_support_allows_partial_migration():
    (comp,) = components(_hub_estate())
    plan = comp.solve(_val(trans=True, old_ok=False))
    assert plan.migrated == frozenset({"k0"})
    assert plan.objective == 3 * W


def test_app_level_failure_blocks_contract():
    (comp,) = components(_hub_estate())
    v = _val(trans=True, old_ok=True)
    v[app_fact("gw", "sig")] = False
    assert "k0" not in comp.solve(v).migrated


def test_decisive_ignores_ties_between_equal_plans():
    # two consumers, each reachable two ways only through upgrades with equal cost:
    # flipping one upgrade fact changes WHICH plan, not the objective -> not decisive alone
    nodes = {"p": Node("p", "S", 1, 1), "c": Node("c", "X", 1, 1)}
    contracts = {"k": Contract("k", "p", "c", "kex", 1)}
    est = Estate(nodes, contracts)
    from phase0.sim.generator import Scenario

    truth = {f: True for f in est.all_facts()}
    know = Knowledge({f: None for f in truth})
    know.values[lib_fact("S", "kex")] = True
    know.values[app_fact("c", "kex")] = True
    know.values[upg_fact("p")] = True
    scen = Scenario(est, truth, know)
    import random

    ctx = Context(scen, Knowledge(dict(know.values)), components(est), {"lib": 1, "app": 1, "vendor": 1}, random.Random(0))
    ctx.refresh()
    # gap exists: consumer needs lib X kex OR upgrade; both unknown -> jointly uncertain
    assert ctx.gap
    f = decisive(ctx)
    assert f in {lib_fact("X", "kex"), upg_fact("c")}


def test_every_strategy_ends_with_correct_plan():
    for seed in range(3):
        scen = generate(seed, n_services=10, n_clients=4)
        for name, sel in STRATEGIES.items():
            r = run(scen, name, sel, "two_tier", seed)
            assert r.final_correct, (name, seed)
            assert r.final_objective == r.true_objective


def test_generator_is_deterministic():
    a, b = generate(42), generate(42)
    assert a.truth == b.truth
    assert a.estate.contracts == b.estate.contracts


def test_generator_independent_of_hash_seed():
    """Regression: truth sampling used to iterate a set, so results changed with PYTHONHASHSEED."""
    import hashlib
    import os
    import subprocess
    import sys

    code = (
        "import json,hashlib;from phase0.sim.generator import generate;"
        "s=generate(3);print(hashlib.sha256(json.dumps([sorted(s.truth.items()),"
        "sorted((k,v) for k,v in s.initial.values.items() if v is not None)]).encode()).hexdigest())"
    )
    outs = set()
    for hs in ("1", "2", "3"):
        env = dict(os.environ, PYTHONHASHSEED=hs)
        outs.add(subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout)
    assert len(outs) == 1
    del hashlib
