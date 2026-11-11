"""Malformed JSON envelope metadata returns BLOCKED, never an exception or PASS."""

import json

import pytest

from szl_evidence_core import UnifiedReceiptChain


def envelope(size=1, algorithm="sha3_256"):
    chain = UnifiedReceiptChain(algorithm)
    for index in range(size):
        chain.emit("kernel", "operation", {"index": index})
    return json.loads(chain.to_envelope())


@pytest.mark.parametrize("value", [[], {}, ["sha3_256"], {"name": "sha3_256"}, None, True, 1, "unknown"])
def test_algorithm_must_be_a_supported_string(value):
    doc = envelope()
    doc["algorithm"] = value
    outcome = UnifiedReceiptChain.verify_json(json.dumps(doc))
    assert not outcome.ok
    assert outcome.status == "BLOCKED"


@pytest.mark.parametrize("size,value", [(0, False), (0, 0.0), (1, True), (1, 1.0), (1, "1"), (1, None), (1, []), (1, {}), (1, -1)])
def test_depth_must_be_a_nonnegative_json_integer(size, value):
    doc = envelope(size)
    doc["depth"] = value
    outcome = UnifiedReceiptChain.verify_json(json.dumps(doc))
    assert not outcome.ok
    assert outcome.status == "BLOCKED"


@pytest.mark.parametrize("algorithm", ["sha256", "sha3_256"])
@pytest.mark.parametrize("size", [0, 1, 3])
def test_generated_envelopes_keep_their_existing_verification(algorithm, size):
    doc = envelope(size, algorithm)
    outcome = UnifiedReceiptChain.verify_json(json.dumps(doc))
    assert outcome == (True, size, -1)
    assert outcome.status == ("PASS" if size else "NOT_RUN")


def test_legacy_list_and_optional_algorithm_default_remain_supported():
    doc = envelope()
    assert UnifiedReceiptChain.verify_json(json.dumps(doc["records"])) == (True, 1, -1)
    del doc["algorithm"]
    assert UnifiedReceiptChain.verify_json(json.dumps(doc)) == (True, 1, -1)
