# Phase 0 pre-registration

This file was written and committed BEFORE running any experiment in `phase0/`.
Its commit timestamp is the evidence.

## Gate 3/4: test-selection competition

### Question

Which strategy reaches a **certified-correct** migration plan with the least probe cost?

### Certification rule (identical for every strategy)

- The optimistic plan treats UNKNOWN facts as true.
- The pessimistic plan treats UNKNOWN facts as false.
- Stop when `objective(pessimistic) == objective(optimistic)`.
- Return the pessimistic plan. It uses only confirmed facts, so it is feasible under the
  hidden truth and optimal under the hidden truth.

### Strategies

1. `random`
2. `criticality` (fact touching the highest total contract criticality)
3. `centrality` (fact of the highest-degree node)
4. `fanin` (fact used by the most contracts in the current optimistic plan)
5. `evoi` (prior P(fail) × contracts affected ÷ cost)
6. `decisive` (two-sided solver sensitivity: facts whose resolution changes the optimistic or pessimistic objective; cheapest first)
7. `test_all` (upper bound)
8. `oracle` (knows the truth; tests only the false facts the optimistic plan uses, then decisive; a heuristic lower bound, not a true minimum)

### Primary metric

Total probe cost until certification.

### Secondary metrics

- probes run
- cost until the optimistic plan first becomes correct under truth
- number of wrong intermediate plans
- blockers found
- wall-clock time

### Cost models

| Model | L2 library twin | L3 app / staging | Vendor / upgrade |
|---|---|---|---|
| uniform | 1 | 1 | 1 |
| two_tier | 1 | 10 | 50 |
| steep | 1 | 30 | 200 |

### Design

- 40 seeds × 3 cost models × 8 strategies
- Graphs from `generator.py` with its own RNG. The generator does not import any selector code.

### Hypotheses and decision rule

- **H1:** `decisive` has lower mean cost than `fanin` under `two_tier` and `steep`.
  The paired bootstrap 95% CI of (fanin − decisive) must be > 0, and the mean reduction must be ≥ 15%.
- **H2:** under `uniform`, the `decisive` advantage over `fanin` is smaller than under `steep`.

If H1 fails, we do NOT claim the decisive selector as a contribution. We use the best
performer and say so.

### Sensitivity

EVoI is run with correct priors and with misspecified priors (all failure probabilities × 0.3).

## Gate 3: solver scaling

- Time for one optimistic solve and for one full decisive-selection pass, at 100 / 1,000 / 10,000 contracts.
- 3 seeds each.
- **Pass:** one solve under 2 s at 1,000 contracts.
- Report 10,000 as is.

## Gate 1: probes (OpenSSL 3.5.4 and 1.1.1w built from source)

Report exactly what happened for:

- capability listing
- hybrid group negotiation
- a classical-only client against a hybrid-only server (must be rejected)
- a server with classical fallback (accepts classical, which a hybrid-required policy must flag)
- ClientHello size with and without the hybrid key share

The Catalyst forged-PQ reproduction needs Bouncy Castle, and Maven Central is blocked in this environment.
That probe is prepared but marked NOT RUN.

## Gate 2: twin validity pilot

This is a pilot only: apps and twins are written by the same author, which is a known circularity.
Report the false-compatible rate (twin says PASS, app says FAIL) and the causes.
