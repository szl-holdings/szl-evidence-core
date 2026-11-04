"""ISO timestamps must have a representable UTC instant before admission."""
import json

import pytest

from test_estate_manifest import DIGEST, NOW, SERVED, SHA, record
from szl_evidence_core.estate_manifest import (
    ManifestError, admit, load_manifest, validate_manifest, validate_record,
)


OVERFLOW_TIMES = [
    "0001-01-01T00:00:00+01:00",
    "9999-12-31T23:59:59-01:00",
]


def observed_record():
    item = record("QUALIFIED")
    item["hf"] = {
        "organization": "SZLHOLDINGS", "asset_type": "space",
        "name": "example", "revision": SHA, "artifact_digest": DIGEST,
        "license": "Apache-2.0", "served_bytes_sha256": SERVED,
        "readback_at": "2026-10-27T19:00:00Z", "source_revision": SHA,
    }
    item["domain"] = {
        "url": "https://example.com", "served_bytes_sha256": SERVED,
        "observed_at": "2026-10-27T19:00:00Z", "source_revision": SHA,
    }
    return item


@pytest.mark.parametrize("timestamp", OVERFLOW_TIMES)
@pytest.mark.parametrize("section, field", [
    ("verification", "freshness"), ("receipt", "issued_at"),
    ("hf", "readback_at"), ("domain", "observed_at"),
])
def test_utc_overflow_in_record_is_denied(section, field, timestamp):
    item = observed_record()
    item[section][field] = timestamp
    expected = f"{section}.{field}: timestamp outside supported UTC range"
    assert expected in validate_record(item)
    admission = admit(item, now=NOW)
    assert admission.decision == "DENY"
    assert expected in admission.reasons


@pytest.mark.parametrize("timestamp", OVERFLOW_TIMES)
def test_utc_overflow_in_manifest_raises_manifest_error(timestamp, tmp_path):
    manifest = {
        "schema_version": "1.0.0", "manifest_id": "estate-1",
        "revision": SHA, "generated_at": timestamp,
        "records": [record()],
    }
    expected = "generated_at: timestamp outside supported UTC range"
    assert expected in validate_manifest(manifest)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ManifestError, match=expected):
        load_manifest(path)


@pytest.mark.parametrize("timestamp", [
    "0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z",
    "0001-01-01T01:00:00+01:00", "9999-12-31T22:59:59-01:00",
])
def test_representable_calendar_boundaries_remain_valid(timestamp):
    item = record("QUALIFIED")
    item["verification"]["freshness"] = timestamp
    assert validate_record(item) == []
    admission = admit(item, now=NOW)
    assert admission.decision == "DENY"
    assert admission.reasons == ("verification.freshness: stale or future evidence",)


def test_offset_equivalent_fresh_evidence_remains_admissible():
    item = observed_record()
    for section, field in [
        ("verification", "freshness"), ("receipt", "issued_at"),
        ("hf", "readback_at"), ("domain", "observed_at"),
    ]:
        item[section][field] = "2026-10-27T21:00:00+02:00"
    assert validate_record(item) == []
    assert admit(item, now=NOW).decision == "ALLOW"
