# CipherAtlas MVP v1.1

**Evidence-Driven Post-Quantum Cryptography (PQC) Migration Rehearsal**

CipherAtlas addresses a migration problem rather than a pure scanning problem: a server may support post-quantum cryptography while a dependent client still fails or silently falls back to classical cryptography. The MVP discovers cryptographic evidence, models one producer-consumer dependency, runs or replays controlled TLS compatibility probes, and changes the migration decision from the observed result.

## What the MVP proves

`DISCOVER → UNDERSTAND PURPOSE → MAP DEPENDENCY → PROBE → DECIDE → SHOW EVIDENCE`

The flagship scenario targets **X25519MLKEM768**. A legacy OpenSSL client can connect successfully when fallback is enabled while actually negotiating **X25519**, so a healthy connection is not enough to claim that the PQ migration target was achieved.

## What is implemented

- Static-only scan of Python, simple TLS/OpenSSL-style configuration, JSON manifests, and X.509 certificates.
- Purpose-aware findings and file/line evidence where available.
- OpenSSL library/version inventory from demo configuration.
- Scan-coverage reporting; unsupported/failed files result in `SCAN_INCOMPLETE`.
- Minimal producer-consumer cryptographic contracts through `cipheratlas.contracts.json`.
- Measured Phase 0 evidence profiles for OpenSSL 3.5.4, 3.0.13, and 1.1.1w.
- Recorded measured probe replay for the Phase 0 compatibility matrix.
- A real local loopback OpenSSL probe when the laptop supports `X25519MLKEM768`.
- Migration states: `READY_FOR_PROBE`, `BLOCKED`, `VALIDATED_IN_TEST_ENV`, `INCONCLUSIVE`.
- Judge-mode challenge presets: silent fallback, hard break, and modern pass.
- Evidence trail, raw result inspection, run history, and downloadable evidence JSON.
- Safe ZIP ingestion limits and path traversal protection.
- No LLM determines a security state or migration result.
- Scanned repository code is **never executed**.

## Fastest Windows / VS Code start

1. Extract the ZIP and open the `CipherAtlas_MVP` folder in VS Code.
2. Double-click `run.bat`, or use the VS Code terminal:

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

3. Open `http://127.0.0.1:8000`.

Install dependencies before the presentation if the demo machine will be offline.

## 90-second judge demo

1. **Overview**: explain the core problem: connection success can hide classical fallback.
2. **Crypto inventory**: show source/config/certificate discovery and coverage.
3. **Migration rehearsal**: click **1 · Silent fallback**.
   - Connection succeeds.
   - Observed group is `X25519`.
   - Target is `X25519MLKEM768`.
   - CipherAtlas returns `BLOCKED` for the migration target.
4. Click **3 · Modern pass**.
   - The measured modern-client run negotiates `X25519MLKEM768`.
   - CipherAtlas returns `VALIDATED_IN_TEST_ENV`.
5. Open **Evidence trail** and download the JSON proof.
6. Optional: select **This laptop · live OpenSSL probe** and rerun against the local OpenSSL installation.

## Important claim boundary

CipherAtlas does **not** claim that a scan proves a system is quantum-safe, secure, verified, or production-ready. `VALIDATED_IN_TEST_ENV` means only that the named condition passed in the exact recorded test environment/version/configuration.

## Current limitations

- Scanner coverage is intentionally narrow for the hackathon MVP.
- Dependency contracts in the demo are supplied by a manifest rather than inferred from a full enterprise environment.
- Reusable stack evidence is only safe when relevant version/build/provider/configuration characteristics match; application-specific overrides can require direct probing.
- Phase 0 stack-reuse savings are simulation findings, not guaranteed real-enterprise savings.
- Public Web PKI migration, real HSM/KMS firmware, vendor appliances, and broad language coverage are outside the MVP.
- The Phase 0 Catalyst experiment is research evidence, not a headline product claim.

## Tests

MVP regression suite:

```bash
python -m pytest -q tests
```

Phase 0 research suite additionally requires `requirements-phase0.txt` and uses the preserved package under `research/phase0`:

```bash
pip install -r requirements-phase0.txt
PYTHONPATH=research python -m pytest -q research/phase0/tests
```

## Repository layout

```text
CipherAtlas_MVP/
├── app/                  # FastAPI backend, scanner, probe, planning, security
├── frontend/             # dependency-free enterprise-style UI
├── sample_project/       # deterministic demo fixture
├── tests/                # MVP regression tests
├── research/phase0/      # preserved Phase 0 experiments + raw results
├── DEMO_GUIDE.md         # stage flow
├── JUDGE_QA.md           # concise technical Q&A
├── REVIEW.md             # final code/red-flag review
├── run.bat               # Windows one-click launcher
└── run.sh                # Linux/macOS launcher
```
