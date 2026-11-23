"""Fail-closed unsigned provenance receipts for szl-evidence-core artifacts.

Every estate artifact (model, dataset, kernel, space build) can carry a
machine-readable provenance receipt binding it to its GitHub source SHA,
HF revision and content digests. Receipts are UNSIGNED by construction:
the ``verified`` field is hard-defaulted to ``False`` and cannot be set
through this API. Signed receipts require the owner-gated signature mint;
until then an honest receipt says UNVERIFIED.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import subprocess
from typing import Optional

__all__ = ["ProvenanceError", "RECEIPT_SCHEMA", "current_git_sha", "emit_receipt"]

RECEIPT_SCHEMA = "szl.evidence-core.provenance-receipt/v0"


class ProvenanceError(ValueError):
    """Raised when a caller tries to forge or force receipt behavior."""


def current_git_sha(path: Optional[str] = None) -> Optional[str]:
    """Return the HEAD SHA of the repo containing ``path`` (or None, honestly)."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except Exception:
        return None
    sha = out.stdout.strip()
    return sha if len(sha) == 40 else None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _artifact_digest(artifact_path: Optional[str], artifact_data: Optional[bytes]) -> Optional[str]:
    if artifact_path is not None:
        with open(artifact_path, "rb") as fh:
            return _sha256_hex(fh.read())
    if artifact_data is not None:
        return _sha256_hex(artifact_data)
    return None


def emit_receipt(
    *,
    git_sha: Optional[str] = None,
    hf_revision: Optional[str] = None,
    dataset_digest: Optional[str] = None,
    kernel_id: Optional[str] = None,
    artifact_path: Optional[str] = None,
    artifact_data: Optional[bytes] = None,
    auto_git_sha: bool = True,
    notes: Optional[str] = None,
) -> dict:
    """Emit an UNSIGNED provenance receipt (pure data; no file I/O).

    ``verified`` is always ``False``: there is no parameter to set it. The
    signature mint that could someday set it is owner-gated estate policy;
    passing ``verified`` as a kwarg raises (it is not accepted).
    """
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "generated": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "git_sha": git_sha if git_sha is not None else (current_git_sha() if auto_git_sha else None),
        "hf_revision": hf_revision,
        "dataset_digest": dataset_digest,
        "kernel_id": kernel_id,
        "artifact_digest": _artifact_digest(artifact_path, artifact_data),
        "verified": False,
        "verification": "UNVERIFIED: unsigned receipt; signature mint is owner-gated; never display as green",
        "notes": notes,
    }
    return json.loads(json.dumps(receipt, sort_keys=True))