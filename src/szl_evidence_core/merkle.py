# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""RFC 9162 Merkle Tree Hash, inclusion and consistency proofs. Stdlib only.

Why. A hash chain proves that a ledger was not edited in the middle. It cannot
hand a third party a short proof that *one* receipt is in it without shipping
the whole ledger, and a checkpoint of the form ``{depth, head}`` cannot be
compared against a later checkpoint to prove nothing was rewritten in between.
Certificate Transparency (RFC 9162), Sigstore's Rekor v2 and Google's
Tessera all solve both with the same construction:

    MTH({})      = HASH()
    MTH({d0})    = HASH(0x00 || d0)
    MTH(D[n])    = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))   k = largest power of two < n

Inclusion proofs are O(log n) hashes; consistency proofs show tree_size m is a
prefix of tree_size n. SCITT's "Checkpointed Local Log" draft
(draft-mih-scitt-checkpointed-local-log) is this construction applied to a
locally kept log, which is exactly what ``UnifiedReceiptChain`` is.

The 0x00 / 0x01 domain separation is what prevents a second-preimage attack
where an interior node is presented as a leaf. Do not remove it.

Verified against the transparency-dev/merkle test vectors (the Sigstore and CT
reference): eight leaf inputs, roots for tree sizes 0..8, and every inclusion
proof for every (index, size) pair. Nothing here is signed; a root hash is a
commitment, and who vouches for it is a separate, out-of-band question.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Iterable, Sequence

__all__ = [
    "MerkleError",
    "leaf_hash",
    "node_hash",
    "mth",
    "inclusion_proof",
    "verify_inclusion",
    "consistency_proof",
    "verify_consistency",
]


class MerkleError(ValueError):
    """A proof or tree argument is malformed."""


def _h(algorithm: str):
    try:
        return hashlib.new(algorithm)
    except ValueError:
        raise MerkleError(f"unknown hash algorithm {algorithm!r}") from None


def leaf_hash(data: bytes, algorithm: str = "sha256") -> bytes:
    h = _h(algorithm); h.update(b"\x00"); h.update(data); return h.digest()


def node_hash(left: bytes, right: bytes, algorithm: str = "sha256") -> bytes:
    h = _h(algorithm); h.update(b"\x01"); h.update(left); h.update(right); return h.digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves: Sequence[bytes], algorithm: str = "sha256") -> bytes:
    """Merkle Tree Hash over leaf *inputs* (not pre-hashed)."""
    n = len(leaves)
    if n == 0:
        return _h(algorithm).digest()
    if n == 1:
        return leaf_hash(leaves[0], algorithm)
    k = _split(n)
    return node_hash(mth(leaves[:k], algorithm), mth(leaves[k:], algorithm), algorithm)


def inclusion_proof(index: int, leaves: Sequence[bytes], algorithm: str = "sha256") -> list[bytes]:
    """RFC 9162 §2.1.3.1 PATH(m, D[n]) for leaf index m, leaf-to-root order."""
    n = len(leaves)
    if not 0 <= index < n:
        raise MerkleError(f"index {index} out of range for tree size {n}")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(index, leaves[:k], algorithm) + [mth(leaves[k:], algorithm)]
    return inclusion_proof(index - k, leaves[k:], algorithm) + [mth(leaves[:k], algorithm)]


def verify_inclusion(leaf: bytes, index: int, tree_size: int, proof: Sequence[bytes],
                     root: bytes, algorithm: str = "sha256") -> bool:
    """RFC 9162 §2.1.3.2. ``leaf`` is the leaf *input*; constant-time root compare."""
    if tree_size <= 0 or not 0 <= index < tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash(leaf, algorithm)
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r, algorithm)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1; sn >>= 1
        else:
            r = node_hash(r, p, algorithm)
        fn >>= 1; sn >>= 1
    return sn == 0 and hmac.compare_digest(r, root)


def consistency_proof(m: int, leaves: Sequence[bytes], algorithm: str = "sha256") -> list[bytes]:
    """RFC 9162 §2.1.4.1 PROOF(m, D[n]): the earlier tree of size m is a prefix."""
    n = len(leaves)
    if not 0 < m <= n:
        raise MerkleError(f"m={m} must satisfy 0 < m <= n={n}")
    if m == n:
        return []
    return _subproof(m, leaves, True, algorithm)


def _subproof(m: int, d: Sequence[bytes], b: bool, algorithm: str) -> list[bytes]:
    n = len(d)
    if m == n:
        return [] if b else [mth(d, algorithm)]
    k = _split(n)
    if m <= k:
        return _subproof(m, d[:k], b, algorithm) + [mth(d[k:], algorithm)]
    return _subproof(m - k, d[k:], False, algorithm) + [mth(d[:k], algorithm)]


def verify_consistency(m: int, n: int, proof: Sequence[bytes], old_root: bytes,
                       new_root: bytes, algorithm: str = "sha256") -> bool:
    """RFC 9162 §2.1.4.2, step for step."""
    if m <= 0 or n < m:
        return False
    if m == n:
        return not proof and hmac.compare_digest(old_root, new_root)
    path = list(proof)
    if not path:
        return False
    if m & (m - 1) == 0:                 # first is an exact power of two
        path = [old_root] + path
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1; sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr, algorithm)
            sr = node_hash(c, sr, algorithm)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1; sn >>= 1
        else:
            sr = node_hash(sr, c, algorithm)
        fn >>= 1; sn >>= 1
    return sn == 0 and hmac.compare_digest(fr, old_root) and hmac.compare_digest(sr, new_root)
