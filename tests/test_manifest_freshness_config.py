"""Invalid freshness policy must not make an expired receipt admissible."""
import pytest

from test_estate_manifest import NOW, record
from szl_evidence_core.estate_manifest import admit


@pytest.mark.parametrize("max_age_seconds", [
    float("nan"), float("inf"), float("-inf"),
    True, False, 0, -1, None, "86400", [], {}, 1.5, 86400.0,
])
def test_invalid_freshness_budget_is_denied(max_age_seconds):
    item = record("QUALIFIED")
    item["verification"]["freshness"] = "2026-10-27T20:00:00Z"
    item["receipt"]["issued_at"] = "2026-10-27T20:00:00Z"
    admission = admit(item, now=NOW, max_age_seconds=max_age_seconds)
    assert admission.decision == "DENY"
    assert "max_age_seconds" in " ".join(admission.reasons)


@pytest.mark.parametrize("max_age_seconds", [float("nan"), float("inf")])
def test_nonfinite_budget_cannot_admit_expired_evidence(max_age_seconds):
    item = record("QUALIFIED")
    item["verification"]["freshness"] = "2020-01-01T00:00:00Z"
    item["receipt"]["issued_at"] = "2020-01-01T00:00:00Z"
    assert admit(item, now=NOW, max_age_seconds=max_age_seconds).decision == "DENY"


def test_positive_integer_budget_preserves_boundary_and_expiry():
    item = record("QUALIFIED")
    assert admit(item, now=NOW, max_age_seconds=3600).decision == "ALLOW"
    assert admit(item, now=NOW, max_age_seconds=3599).decision == "DENY"


def test_large_positive_integer_budget_needs_no_float_conversion():
    assert admit(record("QUALIFIED"), now=NOW,
                 max_age_seconds=10 ** 1000).decision == "ALLOW"

