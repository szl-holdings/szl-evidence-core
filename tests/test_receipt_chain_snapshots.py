"""Receipt commits must own the nested values covered by their digest."""

import copy

import pytest

from szl_evidence_core import ReceiptChain
from szl_evidence_core.canonical import GENESIS, canonical_bytes, digest


@pytest.mark.parametrize("algorithm", ["sha256", "sha3_256", "sha512"])
def test_emit_detaches_nested_payload_before_hashing(algorithm):
    chain = ReceiptChain(algorithm)
    payload = {"sample": {"values": [1, {"reading": 2}]}, "tags": ("a", ["b"])}
    expected = copy.deepcopy(payload)
    expected.update(seq=0, prev=GENESIS)
    expected_digest = digest(canonical_bytes(expected), algorithm)

    assert chain.emit(payload) == expected_digest
    payload["sample"]["values"][1]["reading"] = 999
    payload["sample"]["values"].append(3)
    payload["tags"][1].append("changed")

    assert chain.rows() == [{**expected, "digest": expected_digest}]
    assert chain.verify() == (True, 1, -1)
    chain.emit({"next": True})
    assert chain.rows()[1]["prev"] == expected_digest
    assert chain.verify() == (True, 2, -1)


def test_reusing_payload_does_not_rewrite_earlier_receipts():
    chain = ReceiptChain()
    payload = {"values": [1]}
    first_digest = chain.emit(payload)
    payload["values"].append(2)
    chain.emit(payload)
    payload["values"].clear()

    rows = chain.rows()
    assert rows[0]["values"] == [1]
    assert rows[1]["values"] == [1, 2]
    assert rows[1]["prev"] == first_digest
    assert chain.verify() == (True, 2, -1)


def test_rejected_payload_leaves_existing_history_unchanged():
    chain = ReceiptChain()
    chain.emit({"values": [1]})
    before = chain.rows()
    with pytest.raises(ValueError):
        chain.emit({"values": [float("nan")]})
    assert chain.rows() == before
    assert chain.verify() == (True, 1, -1)
