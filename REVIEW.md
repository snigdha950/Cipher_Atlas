# Final MVP review

## Strong points

- Complete vertical slice from discovery to evidence-backed migration state.
- Real measured TLS evidence rather than mocked compatibility claims.
- Judge-editable scenarios with raw evidence and downloadable JSON.
- Explicit `SCAN_INCOMPLETE` and `INCONCLUSIVE` states.
- Static-only repository handling; no uploaded project execution.
- Purpose-aware RSA/X25519 handling and corrected EC certificate semantics.
- Sophisticated test-selection idea was dropped after it lost its experiment.
- Preserved Phase 0 pre-registration, negative results and raw result files.

## Red flags addressed in v1.1

- Fixed over-broad RSA `.sign()` inference by tracking aliases/key variables.
- EC public keys are no longer mislabeled as ECDSA solely from key type.
- Added OpenSSL library/version discovery in configuration.
- Artifact hashing is deterministic and includes paths/boundaries.
- ZIP ingestion now rejects encrypted entries, traversal, oversize content and suspicious compression ratios.
- Live TLS probe uses a dynamically selected loopback port rather than a hard-coded port.
- Evidence export and decision history make real-time judge challenges inspectable.

## Remaining limitations

- Dependency inference is manifest-driven in the MVP.
- Discovery is not yet benchmarked against a large independent holdout corpus.
- Stack-profile reuse is still a pilot concept and needs non-default application configurations.
- Full Phase 0 test rerun requires OR-Tools; the MVP test suite is independent of it.
- No real HSM/KMS/vendor appliance integration.

## Current engineering assessment

This package is suitable as a hackathon MVP and live technical demonstration. It is not a production security product. The strongest evidence is the reproducible compatibility behavior and transparent negative results, not breadth of integrations.
