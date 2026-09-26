from __future__ import annotations

from typing import Any

TARGET = "X25519MLKEM768"


def migration_decision(probe: dict[str, Any] | None, target: str = TARGET) -> dict[str, Any]:
    if not probe:
        return {
            "state": "READY_FOR_PROBE",
            "headline": "Critical compatibility evidence is missing",
            "reason": "The target may be supported, but this consumer has not been observed negotiating it.",
            "actions": ["Run a direct negotiation probe for this consumer."],
        }
    if probe.get("status") == "INCONCLUSIVE":
        return {
            "state": "INCONCLUSIVE",
            "headline": "Probe could not establish compatibility",
            "reason": probe.get("reason", "The test did not produce reliable evidence."),
            "actions": ["Fix the probe environment and repeat the test."],
        }
    ok = bool(probe.get("handshake_ok"))
    negotiated = probe.get("negotiated_group")
    if ok and negotiated == target:
        return {
            "state": "VALIDATED_IN_TEST_ENV",
            "headline": "Target negotiated in the recorded test environment",
            "reason": f"Handshake succeeded and the observed group was {target}.",
            "actions": ["Run application health and rollback checks before deployment.", "Re-probe after library or relevant configuration changes."],
        }
    if ok and negotiated and negotiated != target:
        return {
            "state": "BLOCKED",
            "headline": "Connection works, but the PQ migration target was not achieved",
            "reason": f"The connection negotiated {negotiated} instead of {target}. This is silent classical fallback.",
            "actions": ["Upgrade or reconfigure the incompatible consumer.", "Keep a controlled transition path only where policy allows.", "Re-run the negotiation probe."],
        }
    return {
        "state": "BLOCKED",
        "headline": "Target migration breaks this tested consumer",
        "reason": probe.get("error_hint") or "The TLS handshake did not complete under the target configuration.",
        "actions": ["Upgrade or replace the incompatible consumer/runtime.", "Re-run the probe after the change."],
    }
