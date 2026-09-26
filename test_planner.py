from app.planner import migration_decision


def test_silent_fallback_is_blocked():
    d = migration_decision({"handshake_ok": True, "negotiated_group": "X25519"})
    assert d["state"] == "BLOCKED"
    assert "fallback" in d["reason"].lower()


def test_target_negotiation_is_scoped_validation():
    d = migration_decision({"handshake_ok": True, "negotiated_group": "X25519MLKEM768"})
    assert d["state"] == "VALIDATED_IN_TEST_ENV"


def test_missing_evidence_requires_probe():
    assert migration_decision(None)["state"] == "READY_FOR_PROBE"


def test_probe_failure_blocks():
    d = migration_decision({"handshake_ok": False, "error_hint": "handshake failure"})
    assert d["state"] == "BLOCKED"
