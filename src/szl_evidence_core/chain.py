# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""SHA3-256 hash-chained receipt ledgers, extracted from the kernel estate.

Provenance. This module is a faithful port, not a redesign, of::

    szl-holdings/szl-kernels  torch-ext/szl_kernels/_chain.py
    commit c2b2fc81354b7be6294f50f90d84da2a0ec0cffc
    blob   87118ab32287dad4b64a6c0a92d61ac3bf58d05c
    sha256 9344309099b3b8e8f4a30f7d412c699ea8637a09d3cbf35d101d8c3beca01b56

That file is already the estate's de-facto canonical: ``szl-blocked`` and
``szl-provctl`` prefer it through a guarded import and fall back to a vendored
copy only when it is not installed. The 2026-10-01 audit found eleven
``_chain.py`` copies in two families, and this module carries both:

``UnifiedReceiptChain``  7 copies (szl-kernels x3 builds, szl-blocked x2,
                        szl-provctl x2). ``emit``/``_digest_body`` identical in
                        all seven; the larger copies are strict supersets.
``ReceiptChain``        4 copies (szl-receipt-attn, szl-block-kv, szl-maskmod,
                        YARQA-ATTN). Byte-different, semantically identical.

Compatibility contract. For every input the originals accept as valid JSON,
this module produces the identical digest, identical ``(ok, depth, first_break)``
tuple, identical ``to_json()`` bytes and identical ``szl.receipt-checkpoint/v1``
checkpoint. The hashed body stays ``{seq,kernel,op,attrs,prev}`` under SHA3-256
with a 64-zero genesis. ``python -m szl_evidence_core compat <estate-root>``
proves this against the original files rather than asserting it.

Intentional behaviour changes, both fail-closed and both loud:

1. ``ReceiptChain.emit`` refuses a payload carrying the reserved keys ``seq``
   or ``prev`` instead of silently overwriting them. Six call sites across the
   four source repositories were checked; none passes either key.
2. ``ReceiptChain`` canonicalises with ``allow_nan=False``. Three of its four
   sources did not, so a NaN payload hashed locally and produced a receipt no
   conforming JSON reader could parse. Valid payloads hash to the same bytes.

Additive surface, which changes no hashed bytes: ``to_envelope()`` wraps the
legacy record list in an object that declares the canon profile, algorithm and
genesis, so a verifier that did not write the chain no longer has to guess
which of the estate's two hash algorithms was used. ``verify_json`` accepts
both the legacy bare list and the envelope.

What this is not. Unanchored verification checks internal consistency, not
complete history, authorship or execution. Timestamps are outside the hashed
body. The digest is an integrity fingerprint, not a signature; the honest tier
label is UNSIGNED_HONEST.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import re
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from .canonical import (
    ALGORITHMS,
    CANON_RECEIPT,
    GENESIS,
    UNSIGNED_HONEST,
    CanonicalizationError,
    canonical_bytes,
    digest,
)

try:  # torch is optional at import time so the chain stays inspectable headless
    import torch  # noqa: F401
    _HAS_TORCH = True
except Exception:  # pragma: no cover - exercised only in torch-less envs
    _HAS_TORCH = False

__all__ = [
    "GENESIS",
    "KERNEL_ALGORITHM",
    "CHECKPOINT_SCHEMA",
    "CHECKPOINT_V2_SCHEMA",
    "ENVELOPE_SCHEMA",
    "ChainVerification",
    "ReceiptChain",
    "UnifiedReceiptChain",
    "tensor_digest",
]

#: Every one of the eleven source copies used SHA3-256. Chains they have
#: already written must keep verifying, so that stays the default here even
#: though the receipt estate at large is split 22 SHA-256 / 13 SHA3-256. The
#: algorithm is declared in the envelope; it is never part of the hashed body.
KERNEL_ALGORITHM = "sha3_256"

CHECKPOINT_SCHEMA = "szl.receipt-checkpoint/v1"
CHECKPOINT_V2_SCHEMA = "szl.receipt-checkpoint/v2"  # RFC 9162 Merkle tree head over record digests
ENVELOPE_SCHEMA = "szl.receipt-envelope/v1"

# Default rounding precision for tensor fingerprints. MUST match
# szl_governed_norm._receipt._tensor_digest so a unified-chain norm receipt's
# out_digest is bit-identical to the standalone kernel's.
_DECIMALS = 6
_DIGEST_CHUNK_ELEMENTS = 4096
_HEX64 = re.compile(r"[0-9a-f]{64}")


def tensor_digest(t: "Any", decimals: int = _DECIMALS) -> str:
    """Deterministic SHA3-256 over a tensor's rounded float32 contents.

    Identical scheme to the source: round to a fixed number of decimals,
    integerize, hash the raw little-endian int64 bytes. Stable across
    devices/dtypes for the same logical values. Integrity fingerprint, not a
    signature, and equal fingerprints are not evidence that the original tensor
    bytes were equal.

    Without torch the source hashed ``repr(t)``. That is preserved for
    byte-compatibility but labelled: a repr is not a stable encoding.
    """
    if _HAS_TORCH and hasattr(t, "detach"):
        flat = t.detach().to(torch.float32).reshape(-1)
        scaled = torch.round(flat * (10 ** decimals)).to(torch.int64).cpu()
        h = hashlib.sha3_256()
        for chunk in scaled.split(_DIGEST_CHUNK_ELEMENTS):
            values = chunk.tolist()
            h.update(struct.pack(f"<{len(values)}q", *values))
        return h.hexdigest()
    return hashlib.sha3_256(repr(t).encode("utf-8")).hexdigest()


class ChainVerification(tuple):
    """``(ok, depth, first_break)`` with a named reason and a fail-closed status.

    Equal to, and unpackable as, the plain tuple every source copy returned, so
    ``ok, depth, bad = chain.verify()`` and ``assert chain.verify() == (True, 3, -1)``
    both keep working. ``first_break`` is -1 when the chain is intact.
    """

    # No __slots__: a tuple subclass without them carries a __dict__, which is
    # the only way to attach the reason without changing the tuple's items.

    def __new__(cls, ok: bool, depth: int, first_break: int,
                reason: str = "") -> "ChainVerification":
        self = super().__new__(cls, (bool(ok), int(depth), int(first_break)))
        self._reason = reason
        return self

    @property
    def ok(self) -> bool:
        return self[0]

    @property
    def depth(self) -> int:
        return self[1]

    @property
    def first_break(self) -> int:
        return self[2]

    @property
    def reason(self) -> str:
        return getattr(self, "_reason", "")

    @property
    def status(self) -> str:
        """An empty chain proves nothing, so it is NOT_RUN rather than PASS."""
        if not self.ok:
            return "BLOCKED"
        return "PASS" if self.depth else "NOT_RUN"

    def __repr__(self) -> str:
        return (f"ChainVerification(ok={self.ok}, depth={self.depth}, "
                f"first_break={self.first_break}, reason={self.reason!r})")


def _check_algorithm(algorithm: str) -> str:
    if algorithm not in ALGORITHMS:
        raise CanonicalizationError(
            f"unknown algorithm {algorithm!r}; supported: {sorted(ALGORITHMS)}")
    return algorithm


# --------------------------------------------------------------------------- #
# UnifiedReceiptChain: faithful port of szl_kernels/_chain.py                 #
# --------------------------------------------------------------------------- #

class UnifiedReceiptChain:
    """Append-only, SHA3-256 hash-chained log spanning MANY kernel ops.

    Each receipt body is canonical JSON with a fixed, sorted schema
    ``{seq, kernel, op, attrs, prev}``; ``digest`` is the hash of that body
    and ``ts`` sits outside it so the digest is reproducible offline.

    ``verify()`` re-walks the chain and returns ``(ok, depth, first_break)``.
    Without a separately retained checkpoint this establishes only internal
    consistency: a valid prefix or a fully recomputed history can still pass.
    Pass ``expected_head`` and ``expected_depth`` from trusted external custody
    to detect replacement. Public read methods return detached snapshots.
    """

    def __init__(self, algorithm: str = KERNEL_ALGORITHM) -> None:
        self._lock = threading.RLock()
        self._records: List[Dict[str, Any]] = []
        self._algorithm = _check_algorithm(algorithm)

    @property
    def algorithm(self) -> str:
        return self._algorithm

    # -- canonical hashing (sorted keys, tight separators, strict no-NaN) --
    @staticmethod
    def _digest_body(body: Dict[str, Any], algorithm: str = KERNEL_ALGORITHM) -> str:
        # Byte-identical to the source for sha3_256:
        #   json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return digest(canonical_bytes(body, check=False), algorithm)

    def emit(self, kernel: str, op: str, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Append one op-agnostic receipt and return it (with digest + ts).

        ``attrs`` must be JSON-able and finite. A non-finite value would make
        the receipt un-attestable by a strict third-party verifier, so it is
        rejected at hash time rather than discovered at verify time.
        """
        with self._lock:
            prev = self._records[-1]["digest"] if self._records else GENESIS
            seq = len(self._records)
            body = {
                "seq": seq,
                "kernel": str(kernel),
                "op": str(op),
                "attrs": self._snapshot_attrs(attrs),
                "prev": prev,
            }
            body_digest = self._digest_body(body, self._algorithm)
            rec = dict(body, digest=body_digest, ts=time.time())
            self._records.append(rec)
            return copy.deepcopy(rec)

    @staticmethod
    def _snapshot_attrs(attrs: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(attrs, dict):
            raise TypeError("receipt attrs must be a JSON object")
        # Detached JSON value, as the source does; later caller mutation cannot
        # invalidate stored history or future prev-links.
        return json.loads(json.dumps(attrs, sort_keys=True, allow_nan=False))

    def checkpoint(self) -> Dict[str, Any]:
        """Atomically capture depth/head; preserve it OUTSIDE this chain.

        This unsigned dictionary has no authentication by itself. The caller
        must bind it to a separately trusted signed receipt or retained record.
        """
        with self._lock:
            if not self._verify_records(self._records, algorithm=self._algorithm)[0]:
                raise ValueError("cannot checkpoint an inconsistent chain")
            return {
                "schema": CHECKPOINT_SCHEMA,
                "depth": len(self._records),
                "head": self._records[-1]["digest"] if self._records else GENESIS,
            }

    # -- Merkle commitments (additive; the hashed record body is untouched) --
    def _leaves(self) -> List[bytes]:
        return [bytes.fromhex(r["digest"]) for r in self._records]

    def checkpoint_v2(self) -> Dict[str, Any]:
        """RFC 9162 tree head over the record digests, plus the v1 fields.

        Unlike v1's ``{depth, head}``, a tree head lets a third party verify
        that one receipt is in the ledger from an O(log n) inclusion proof, and
        lets two checkpoints be checked for append-only consistency. Same lock,
        same consistency precondition as v1. Still unsigned: a root is a
        commitment, and who vouches for it is out of band.
        """
        from .merkle import mth

        with self._lock:
            if not self._verify_records(self._records, algorithm=self._algorithm)[0]:
                raise ValueError("cannot checkpoint an inconsistent chain")
            return {
                "schema": CHECKPOINT_V2_SCHEMA,
                "depth": len(self._records),
                "head": self._records[-1]["digest"] if self._records else GENESIS,
                "tree_size": len(self._records),
                "root_hash": mth(self._leaves(), self._algorithm).hex(),
                "hash": self._algorithm,
                "leaf": "record digest bytes; RFC 9162 0x00/0x01 domain separation",
            }

    def inclusion_proof(self, seq: int) -> Dict[str, Any]:
        """Proof that record ``seq`` is in the ledger at the current tree size."""
        from .merkle import inclusion_proof as _proof

        with self._lock:
            leaves = self._leaves()
            if not 0 <= seq < len(leaves):
                raise ValueError(f"seq {seq} out of range for {len(leaves)} records")
            return {
                "schema": "szl.receipt-inclusion/v1",
                "seq": seq,
                "tree_size": len(leaves),
                "leaf": leaves[seq].hex(),
                "proof": [p.hex() for p in _proof(seq, leaves, self._algorithm)],
                "hash": self._algorithm,
            }

    @staticmethod
    def verify_inclusion_proof(proof: Dict[str, Any], checkpoint: Dict[str, Any]) -> bool:
        """Check an inclusion proof against a v2 checkpoint. No ledger needed."""
        from .merkle import verify_inclusion

        try:
            if checkpoint.get("schema") != CHECKPOINT_V2_SCHEMA:
                return False
            if proof.get("tree_size") != checkpoint.get("tree_size") or proof.get("hash") != checkpoint.get("hash"):
                return False
            return verify_inclusion(
                bytes.fromhex(proof["leaf"]), int(proof["seq"]), int(proof["tree_size"]),
                [bytes.fromhex(p) for p in proof["proof"]],
                bytes.fromhex(checkpoint["root_hash"]), checkpoint["hash"])
        except (KeyError, TypeError, ValueError):
            return False

    # -- convenience emitters that enforce the honesty schema per kernel ----
    def emit_norm(self, op: str, x: "Any", out: "Any", eps: float) -> Dict[str, Any]:
        """Record a governed-norm op. ``out_digest`` matches szl_governed_norm."""
        return self.emit(
            "governed_norm",
            op,
            {
                "in_shape": list(getattr(x, "shape", [])),
                "in_dtype": str(getattr(x, "dtype", "")).replace("torch.", ""),
                "eps": float(eps),
                "out_digest": tensor_digest(out),
            },
        )

    def emit_lambda(self, score: float, threshold: float,
                    passed: bool, k: int) -> Dict[str, Any]:
        """Record an ADVISORY Λ-gate evaluation.

        ``advisory`` is hard-coded True and ``lambda_status`` is stamped on every
        entry so the chain is self-documenting: a recorded pass is never proven
        trust. Λ uniqueness is Conjecture 1 and remains open.
        """
        return self.emit(
            "lambda_gate",
            "lambda_gate",
            {
                "score": float(score),
                "threshold": float(threshold),
                "passed": bool(passed),
                "k": int(k),
                "advisory": True,
                "lambda_status": "Conjecture 1 (open) — advisory only, NOT proven trust",
            },
        )

    def emit_energy(self, measurement: Dict[str, Any]) -> Dict[str, Any]:
        """Record an energy reading VERBATIM (label + joules as given).

        ``joules`` may be None (UNAVAILABLE/UNKNOWN) and is recorded as None,
        never upgraded to a fabricated number.
        """
        joules = measurement.get("joules", None)
        return self.emit(
            "energy_core",
            "measure_energy",
            {
                "label": str(measurement.get("label", "UNKNOWN")),
                "joules": (None if joules is None else float(joules)),
                "source": str(measurement.get("source", "")),
            },
        )

    # -- read surface --------------------------------------------------------
    def head(self) -> str:
        with self._lock:
            return self._records[-1]["digest"] if self._records else GENESIS

    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def __len__(self) -> int:
        return self.count()

    def tail(self, n: int = 10) -> List[Dict[str, Any]]:
        if type(n) is not int or n < 0:
            raise ValueError("tail length must be a nonnegative integer")
        with self._lock:
            return copy.deepcopy(self._records[-n:]) if n else []

    def kernels_touched(self) -> List[str]:
        """Distinct kernel labels in first-seen order. Labels, not proof of execution."""
        with self._lock:
            seen: List[str] = []
            for r in self._records:
                if r["kernel"] not in seen:
                    seen.append(r["kernel"])
            return seen

    # -- verification --------------------------------------------------------
    @staticmethod
    def _validate_checkpoint(expected_head: Optional[str],
                             expected_depth: Optional[int]) -> None:
        if expected_head is None and expected_depth is None:
            return
        if (not isinstance(expected_head, str)
                or _HEX64.fullmatch(expected_head) is None
                or type(expected_depth) is not int or expected_depth < 0):
            raise ValueError("checkpoint requires a full lowercase head and nonnegative depth")
        if (expected_depth == 0) != (expected_head == GENESIS):
            raise ValueError("genesis checkpoint must have exactly zero depth")

    @staticmethod
    def _verify_records(
        records: Any,
        *,
        expected_head: Optional[str] = None,
        expected_depth: Optional[int] = None,
        algorithm: str = KERNEL_ALGORITHM,
    ) -> ChainVerification:
        # Checkpoint argument errors are programmer errors, not corrupt history.
        UnifiedReceiptChain._validate_checkpoint(expected_head, expected_depth)
        if not isinstance(records, list):
            return ChainVerification(False, 0, 0, "records is not a list")
        depth = len(records)
        fields = {"seq", "kernel", "op", "attrs", "prev", "digest"}
        prev = GENESIS
        for i, rec in enumerate(records):
            try:
                if (not isinstance(rec, dict) or set(rec) not in (fields, fields | {"ts"})
                        or type(rec["seq"]) is not int or rec["seq"] != i
                        or not isinstance(rec["kernel"], str)
                        or not isinstance(rec["op"], str)
                        or not isinstance(rec["attrs"], dict)
                        or not isinstance(rec["prev"], str)
                        or _HEX64.fullmatch(rec["prev"]) is None
                        or not isinstance(rec["digest"], str)
                        or _HEX64.fullmatch(rec["digest"]) is None
                        or ("ts" in rec and (type(rec["ts"]) not in (int, float)
                                            or not math.isfinite(rec["ts"])))):
                    return ChainVerification(False, depth, i, f"record {i}: malformed")
                body = {key: rec[key] for key in ("seq", "kernel", "op", "attrs", "prev")}
                actual = UnifiedReceiptChain._digest_body(body, algorithm)
                if rec["prev"] != prev:
                    return ChainVerification(False, depth, i, f"record {i}: prev-link broken")
                if not hmac.compare_digest(rec["digest"], actual):
                    return ChainVerification(False, depth, i, f"record {i}: digest mismatch")
                prev = rec["digest"]
            except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
                return ChainVerification(False, depth, i, f"record {i}: {type(exc).__name__}")
        if expected_head is not None:
            if depth != expected_depth or not hmac.compare_digest(prev, expected_head):
                # Internally consistent but not the expected extent/history.
                # Report the boundary, not a fake row.
                return ChainVerification(False, depth, min(depth, expected_depth),
                                         "checkpoint mismatch: head or depth")
        return ChainVerification(True, depth, -1, "chain intact")

    def verify(self, *, expected_head: Optional[str] = None,
               expected_depth: Optional[int] = None) -> ChainVerification:
        """Verify consistency, optionally against a separately retained checkpoint."""
        with self._lock:
            return self._verify_records(
                self._records, expected_head=expected_head,
                expected_depth=expected_depth, algorithm=self._algorithm)

    # -- serialisation -------------------------------------------------------
    def to_json(self) -> str:
        """Legacy export: the bare record list, byte-identical to the source.

        Preserve an independently trusted checkpoint alongside it. The list
        does not say which algorithm produced it; use ``to_envelope`` when the
        reader is not the writer.
        """
        with self._lock:
            return json.dumps(self._records, sort_keys=True,
                              separators=(",", ":"), allow_nan=False)

    def to_envelope(self) -> str:
        """Self-describing export. Additive; the records inside are unchanged."""
        with self._lock:
            return json.dumps({
                "schema": ENVELOPE_SCHEMA,
                "canon": CANON_RECEIPT,
                "algorithm": self._algorithm,
                "genesis": GENESIS,
                "trust": UNSIGNED_HONEST,
                "depth": len(self._records),
                "head": self._records[-1]["digest"] if self._records else GENESIS,
                "records": self._records,
            }, sort_keys=True, separators=(",", ":"), allow_nan=False)

    def export_with_checkpoint(self) -> Tuple[str, Dict[str, Any]]:
        """Capture one export and matching checkpoint under the same lock."""
        with self._lock:
            checkpoint = self.checkpoint()
            return self.to_json(), checkpoint

    @staticmethod
    def verify_json(blob: str, *, expected_head: Optional[str] = None,
                    expected_depth: Optional[int] = None) -> ChainVerification:
        """Verify strict JSON, then consistency and an optional external checkpoint.

        Accepts the legacy bare list (algorithm assumed SHA3-256, as every
        source copy used) or an envelope (algorithm read from the envelope).
        Duplicate keys, non-finite constants, malformed records and wrong
        sequence ordinals are rejected. Invalid JSON returns ``(False, 0, 0)``.
        """
        UnifiedReceiptChain._validate_checkpoint(expected_head, expected_depth)

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result

        def reject_constant(value):
            raise ValueError("nonfinite JSON constant")

        if not isinstance(blob, str):
            return ChainVerification(False, 0, 0, "blob is not a str")
        try:
            doc = json.loads(blob, object_pairs_hook=unique_object,
                             parse_constant=reject_constant)
        except (ValueError, TypeError, OverflowError, RecursionError) as exc:
            return ChainVerification(False, 0, 0, f"not strict JSON: {exc}")

        algorithm = KERNEL_ALGORITHM
        records = doc
        if isinstance(doc, dict):
            if doc.get("schema") != ENVELOPE_SCHEMA or "records" not in doc:
                return ChainVerification(False, 0, 0, "object is not a receipt envelope")
            algorithm = doc.get("algorithm", KERNEL_ALGORITHM)
            if algorithm not in ALGORITHMS:
                return ChainVerification(False, 0, 0, f"envelope algorithm {algorithm!r} unknown")
            if doc.get("genesis", GENESIS) != GENESIS:
                return ChainVerification(False, 0, 0, "envelope genesis is not the shared genesis")
            records = doc["records"]
            outcome = UnifiedReceiptChain._verify_records(
                records, expected_head=expected_head,
                expected_depth=expected_depth, algorithm=algorithm)
            if outcome.ok:
                claimed_head = doc.get("head")
                actual_head = records[-1]["digest"] if records else GENESIS
                if doc.get("depth") != len(records) or claimed_head != actual_head:
                    return ChainVerification(False, len(records), len(records),
                                             "envelope head/depth disagree with records")
            return outcome
        return UnifiedReceiptChain._verify_records(
            records, expected_head=expected_head,
            expected_depth=expected_depth, algorithm=algorithm)


# --------------------------------------------------------------------------- #
# ReceiptChain: faithful port of the four minimal payload chains              #
# --------------------------------------------------------------------------- #

class ReceiptChain:
    """Minimal payload chain from szl-receipt-attn, szl-block-kv, szl-maskmod, YARQA-ATTN.

    ``emit(payload) -> digest`` and ``verify() -> (ok, count, first_break)``
    exactly as the four sources, so a consumer repoints its import and changes
    nothing else. Row shape is ``{**payload, seq, prev, digest}``; the digest
    covers everything but ``digest``.
    """

    def __init__(self, algorithm: str = KERNEL_ALGORITHM) -> None:
        self._lock = threading.RLock()
        self._rows: List[Dict[str, Any]] = []
        self._algorithm = _check_algorithm(algorithm)

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def emit(self, payload: Dict[str, Any]) -> str:
        if not isinstance(payload, dict):
            raise TypeError(f"payload must be a dict, got {type(payload).__name__}")
        if "seq" in payload or "prev" in payload or "digest" in payload:
            # The sources silently overwrote these. A caller who set them would
            # believe they recorded something the chain did not.
            raise ValueError("payload must not define reserved keys seq, prev or digest")
        with self._lock:
            prev = self._rows[-1]["digest"] if self._rows else GENESIS
            body = dict(payload)
            body["seq"] = len(self._rows)
            body["prev"] = prev
            # check=True refuses NaN/Inf and non-string keys at emit time.
            row_digest = digest(canonical_bytes(body, check=True), self._algorithm)
            self._rows.append({**body, "digest": row_digest})
            return row_digest

    def verify(self) -> ChainVerification:
        with self._lock:
            prev = GENESIS
            for i, row in enumerate(self._rows):
                body = {k: v for k, v in row.items() if k != "digest"}
                if row.get("prev") != prev:
                    return ChainVerification(False, i, i, f"row {i}: prev-link broken")
                try:
                    actual = digest(canonical_bytes(body, check=False), self._algorithm)
                except (ValueError, TypeError) as exc:
                    return ChainVerification(False, i, i, f"row {i}: {type(exc).__name__}")
                if not hmac.compare_digest(actual, str(row.get("digest", ""))):
                    return ChainVerification(False, i, i, f"row {i}: digest mismatch")
                prev = row["digest"]
            return ChainVerification(True, len(self._rows), -1, "chain intact")

    def head(self) -> Optional[str]:
        with self._lock:
            return self._rows[-1]["digest"] if self._rows else None

    def rows(self) -> List[Dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._rows)

    def __len__(self) -> int:
        with self._lock:
            return len(self._rows)
