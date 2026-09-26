# Validation record — 26 Sep 2026

Validation performed on the generated MVP package in the build environment.

## MVP regression tests

`python -m pytest -q tests`

Result: **14 passed**.

## API smoke checks

- `/api/health`: PASS
- `/api/sample-scan`: PASS
- Bundled sample coverage: 6/6 files analyzed, 100%, 0 parse failures
- Purpose-aware RSA signature finding: PASS
- OpenSSL 3.5.4 version inventory: PASS

## Rehearsal cases

- OpenSSL 3.0.13 + hybrid/fallback → connection evidence uses X25519 → `BLOCKED`: PASS
- OpenSSL 3.0.13 + hybrid-only → handshake failure → `BLOCKED`: PASS
- OpenSSL 3.5.4 + hybrid-only → X25519MLKEM768 → `VALIDATED_IN_TEST_ENV`: PASS

## Fresh local live probe in build environment

Local OpenSSL: **3.5.5**. Target group `X25519MLKEM768` was available. CipherAtlas' loopback harness completed a TLS handshake and observed `X25519MLKEM768`, producing `VALIDATED_IN_TEST_ENV`.

This result is scoped to that build environment and is not a claim about another laptop.

## Phase 0 preservation

The original Phase 0 code and raw results are bundled under `research/phase0/`. The full Phase 0 simulation suite was not rerun during this packaging pass because OR-Tools is not installed in the packaging runtime. Use `requirements-phase0.txt` to reproduce it separately.
