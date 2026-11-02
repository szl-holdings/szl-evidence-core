"""PROVED admission requires an integer zero, not merely a value equal to it."""
import pytest

from test_estate_manifest import NOW, SHA, record
from szl_evidence_core.estate_manifest import admit


def proved_record():
    item = record("PROVED")
    item["verification"]["proof"] = {
        "lake_build": "PASS",
        "theorem_symbol": "Example.theorem",
        "axioms": [],
        "sorry_count": 0,
        "cross_check": "PASS",
        "source_revision": SHA,
    }
    return item


@pytest.mark.parametrize("sorry_count", [
    False, True, 0.0, -0.0, 1.0, float("nan"), float("inf"),
    None, "0", [], {}, -1, 1,
])
def test_proved_claim_rejects_non_integer_or_nonzero_sorry_count(sorry_count):
    item = proved_record()
    item["verification"]["proof"]["sorry_count"] = sorry_count
    admission = admit(item, now=NOW)
    assert admission.decision == "DENY"
    assert not admission.allowed
    assert "proof witness is not clean" in admission.reasons


def test_proved_claim_accepts_integer_zero_sorry_count():
    admission = admit(proved_record(), now=NOW)
    assert admission.decision == "ALLOW"
    assert admission.allowed


def test_proved_claim_still_requires_sorry_count():
    item = proved_record()
    del item["verification"]["proof"]["sorry_count"]
    admission = admit(item, now=NOW)
    assert admission.decision == "DENY"
    assert "proof.sorry_count: required" in admission.reasons
