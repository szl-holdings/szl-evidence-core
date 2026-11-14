"""Receipt proof envelopes cannot weaken the underlying Merkle admission checks."""
from copy import deepcopy

import pytest

from szl_evidence_core import UnifiedReceiptChain


def receipt_proof():
    chain = UnifiedReceiptChain()
    chain.emit("kernel", "operation", {"value": 1})
    return chain.inclusion_proof(0), chain.checkpoint_v2()


@pytest.mark.parametrize("algorithm", ["sha256", "sha3_256"])
@pytest.mark.parametrize("size", [1, 2, 5])
def test_generated_receipt_proofs_remain_valid(algorithm, size):
    chain = UnifiedReceiptChain(algorithm)
    for index in range(size):
        chain.emit("kernel", "operation", {"index": index})
    checkpoint = chain.checkpoint_v2()
    for index in range(size):
        assert chain.verify_inclusion_proof(chain.inclusion_proof(index), checkpoint)


@pytest.mark.parametrize("value", [False, True, 0.0, 0.9, "0", None, float("nan"), float("inf")])
def test_sequence_requires_an_integer(value):
    proof, checkpoint = receipt_proof()
    proof["seq"] = value
    assert not UnifiedReceiptChain.verify_inclusion_proof(proof, checkpoint)


@pytest.mark.parametrize("value", [True, 1.0, 1.9, "1", None, float("nan"), float("inf")])
@pytest.mark.parametrize("target", ["proof", "checkpoint", "both"])
def test_each_tree_size_requires_an_integer(value, target):
    proof, checkpoint = receipt_proof()
    if target in ("proof", "both"):
        proof["tree_size"] = value
    if target in ("checkpoint", "both"):
        checkpoint["tree_size"] = value
    assert not UnifiedReceiptChain.verify_inclusion_proof(proof, checkpoint)


@pytest.mark.parametrize("target", ["proof", "checkpoint"])
@pytest.mark.parametrize("value", [None, [], "not an envelope", 0])
def test_non_dictionary_envelopes_are_rejected(target, value):
    proof, checkpoint = receipt_proof()
    if target == "proof":
        proof = value
    else:
        checkpoint = value
    assert not UnifiedReceiptChain.verify_inclusion_proof(proof, checkpoint)


@pytest.mark.parametrize("value", [None, "szl.receipt-checkpoint/v2", "szl.receipt-inclusion/v999"])
def test_proof_schema_is_required(value):
    proof, checkpoint = receipt_proof()
    if value is None:
        del proof["schema"]
    else:
        proof["schema"] = value
    assert not UnifiedReceiptChain.verify_inclusion_proof(proof, checkpoint)


def test_commitment_mismatches_still_fail():
    proof, checkpoint = receipt_proof()
    for field, value in [("seq", 1), ("tree_size", 2), ("leaf", "00" * 32), ("hash", "sha256"), ("proof", ["00" * 32])]:
        invalid = deepcopy(proof)
        invalid[field] = value
        assert not UnifiedReceiptChain.verify_inclusion_proof(invalid, checkpoint)
    invalid_checkpoint = deepcopy(checkpoint)
    invalid_checkpoint["root_hash"] = "00" * 32
    assert not UnifiedReceiptChain.verify_inclusion_proof(proof, invalid_checkpoint)


@pytest.mark.parametrize("value", ["", {}, (), None])
def test_path_requires_a_list_even_when_no_sibling_hashes_are_needed(value):
    proof, checkpoint = receipt_proof()
    proof["proof"] = value
    assert not UnifiedReceiptChain.verify_inclusion_proof(proof, checkpoint)
