"""Malformed proof metadata must not become a verified tree commitment."""
import hashlib

import pytest

from szl_evidence_core import merkle as M


@pytest.mark.parametrize("root", [b"", b"x", b"x" * 31, b"x" * 33, "x" * 32, None])
def test_equal_size_consistency_rejects_malformed_roots(root):
    assert M.verify_consistency(1, 1, [], root, root) is False


@pytest.mark.parametrize("size", [True, False, 1.0, "1", None])
def test_sizes_are_integers_not_coerced_metadata(size):
    root = M.mth([b"leaf"])
    assert M.verify_consistency(size, size, [], root, root) is False
    assert M.verify_inclusion(b"leaf", 0, size, [], root) is False
    assert M.verify_inclusion(b"leaf", size, 1, [], root) is False


@pytest.mark.parametrize("proof", [None, "", b"", [b""], [b"x" * 31], [b"x" * 33], ["x" * 32]])
def test_malformed_proof_paths_are_rejected(proof):
    leaves = [b"first", b"second"]
    assert M.verify_inclusion(leaves[0], 0, 2, proof, M.mth(leaves)) is False
    assert M.verify_consistency(1, 2, proof, M.mth(leaves[:1]), M.mth(leaves)) is False
    assert M.verify_consistency(1, 1, proof, M.mth(leaves[:1]), M.mth(leaves[:1])) is False


@pytest.mark.parametrize("algorithm", ["sha256", "sha3_256", "sha512"])
def test_valid_proofs_and_empty_tree_hash_preserve_algorithm_contract(algorithm):
    leaves = [b"", b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"]
    assert M.mth([], algorithm) == hashlib.new(algorithm).digest()
    # The API has always required a positive earlier size for consistency.
    assert M.verify_consistency(0, 1, [], M.mth([], algorithm), M.mth(leaves[:1], algorithm), algorithm) is False
    for size in range(1, len(leaves) + 1):
        root = M.mth(leaves[:size], algorithm)
        for index in range(size):
            path = M.inclusion_proof(index, leaves[:size], algorithm)
            assert M.verify_inclusion(leaves[index], index, size, path, root, algorithm)
        for old_size in range(1, size + 1):
            path = M.consistency_proof(old_size, leaves[:size], algorithm)
            assert M.verify_consistency(old_size, size, path, M.mth(leaves[:old_size], algorithm), root, algorithm)


def test_same_size_validation_still_checks_selected_algorithm():
    root = M.mth([b"leaf"])
    with pytest.raises(M.MerkleError):
        M.verify_consistency(1, 1, [], root, root, "not-a-hash")
    with pytest.raises(M.MerkleError):
        M.verify_consistency(1, 1, [], b"", b"", "shake_128")
