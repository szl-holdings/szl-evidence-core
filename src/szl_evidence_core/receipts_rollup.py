# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Per-model receipt bundles and the estate-wide roll-up ledger.

Why this module exists. The HF estate carries 400+ models; the owner directive
of 2026-11-25 asked for every model to "fully showcase the right receipts"
where only three are fully done. Turning that from 418 chores into a burn-down
requires one atomic unit and one spine:

* the **bundle** is four artifacts per model directory: ``eval.json`` (eval
  output with self-describing digests), ``trace.json`` (one seeded inference
  trace), ``provenance.json`` (base weights, dataset revision, mesh job id)
  and ``receipt.md`` (the rendered card). Anything beyond these four is
  gilding; anything less is partial.
* the **roll-up ledger** is one canonical JSON document listing every bundle
  with per-artifact prefixed digests, a status per model
  (``COMPLETE``/``PARTIAL``), census coverage, and a hash chain whose root can
  be committed to GitHub and mirrored to HF. Every model card, dashboard and
  demo must render *from this single signed source*, not from ad-hoc copies.

Fail-closed rules, in the house style:

* A bundle directory declares its model id exactly once, in
  ``provenance.json``; if it disagrees with the directory name the bundle is
  ``PARTIAL`` with the reason recorded, never silently renamed.
* Missing keys, unparsable JSON, empty files: ``PARTIAL`` with reasons. The
  roll-up never invents a digest it did not compute from bytes.
* Against a previous roll-up (CI mode), a model that regresses
  (``COMPLETE`` -> ``PARTIAL`` or gone, or any artifact digest change) makes
  the run exit non-zero. Progress is monotone or the build is red; the ledger
  is never "repaired" by regenerated histories.
* The chain is unsigned-hash-chain honest, mirroring ``canonical`` doctrine:
  it detects tampering by anyone who cannot rewrite the whole chain; it does
  not authenticate the publisher. Do not upgrade those claims here.

Nothing in this module runs an eval, a model, or a network call.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .canonical import (
    GENESIS,
    canonical_bytes,
    digest,
    digest_object,
)

__all__ = [
    "ROLLUP_SCHEMA",
    "BUNDLE_ARTIFACTS",
    "REQUIRED_KEYS",
    "BundleError",
    "load_bundle",
    "build_rollup",
    "verify_rollup",
    "rollup_regressions",
    "main",
]

ROLLUP_SCHEMA = "szl.receipts-rollup/v1"
BUNDLE_ARTIFACTS = ("eval.json", "trace.json", "provenance.json", "receipt.md")
REQUIRED_KEYS: dict[str, tuple[str, ...]] = {
    "eval.json": ("harness", "eval_sha256", "timestamp"),
    "trace.json": ("seed", "prompt_sha256", "completion_sha256"),
    "provenance.json": ("model_id", "base_weights", "dataset_revision", "mesh_job_id"),
}


class BundleError(Exception):
    """Structural failure loading one bundle; recorded, never fatal."""


def _prefixed_file_digest(path: Path) -> str:
    raw = path.read_bytes()
    return "sha256:" + digest(raw, "sha256")


def _load_json_artifact(model_id: str, name: str, path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    problems: list[str] = []
    if not path.is_file():
        return None, [f"missing {name}"]
    raw = path.read_bytes()
    if not raw.strip():
        return None, [f"empty {name}"]
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, [f"unparsable {name}: {exc}"]
    if not isinstance(value, dict):
        return None, [f"{name}: top level must be an object"]
    missing = [k for k in REQUIRED_KEYS[name] if k not in value]
    if missing:
        problems.append(f"{name}: missing keys {sorted(missing)}")
    return value, problems


def load_bundle(bundle_dir: Path) -> dict[str, Any]:
    """Load one model bundle directory into a roll-up entry (fail-closed).

    Returns an entry dict; never raises for content problems (they are
    recorded as ``PARTIAL``). Raises only on non-content misuse (wrong types).
    """
    bundle_dir = Path(bundle_dir)
    model_id = bundle_dir.name
    artifacts: dict[str, str] = {}
    problems: list[str] = []
    provenance: dict[str, Any] | None = None

    for name in BUNDLE_ARTIFACTS:
        path = bundle_dir / name
        if not path.is_file():
            problems.append(f"missing {name}")
            continue
        artifacts[name] = _prefixed_file_digest(path)
        if name == "receipt.md":
            if not path.read_bytes().strip():
                problems.append(f"empty {name}")
        else:
            doc, doc_problems = _load_json_artifact(model_id, name, path)
            problems.extend(doc_problems)
            if doc is not None and name == "provenance.json":
                provenance = doc

    if provenance is not None:
        declared = provenance.get("model_id")
        if declared != model_id:
            problems.append(
                f"provenance model_id {declared!r} != directory {model_id!r}")
    elif not any(p.startswith("missing provenance") or p.startswith("unparsable provenance")
                 or p.startswith("provenance") or p.startswith("empty provenance")
                 for p in problems):
        problems.append("provenance.json not loadable")

    # trust semantics are never inferred here
    return {
        "model_id": model_id,
        "status": "PARTIAL" if problems else "COMPLETE",
        "problems": sorted(problems),
        "artifacts": artifacts,
    }


def _chain_step(prev_link: str, entry_digest: str) -> str:
    return "sha256:" + digest(
        canonical_bytes({"prev": prev_link, "entry": entry_digest}), "sha256")


def build_rollup(bundles_root: Path, *, census: list[str] | None = None) -> dict[str, Any]:
    """Build the roll-up ledger over ``bundles_root`` (deterministic)."""
    bundles_root = Path(bundles_root)
    if not bundles_root.is_dir():
        raise BundleError(f"bundles root {bundles_root} is not a directory")

    entries: list[dict[str, Any]] = []
    for bundle_dir in sorted(p for p in bundles_root.iterdir() if p.is_dir()):
        entry = load_bundle(bundle_dir)
        entry_digest = digest_object(entry)
        entries.append({"model": entry, "entry_digest": entry_digest})

    link = GENESIS
    for item in entries:
        link = _chain_step(link, item["entry_digest"])
        item["model"]["link"] = link
        item["model"]["entry_digest"] = item["entry_digest"]

    models = [item["model"] for item in entries]
    complete = sum(1 for m in models if m["status"] == "COMPLETE")
    partial = sum(1 for m in models if m["status"] == "PARTIAL")
    seen = {m["model_id"] for m in models}

    rollup: dict[str, Any] = {
        "schema": ROLLUP_SCHEMA,
        "bundles_root": bundles_root.name,
        "chain_root": link,
        "counts": {"complete": complete, "partial": partial},
        "models": models,
    }
    if census is not None:
        missing = sorted(mid for mid in census if mid not in seen)
        rollup["census"] = {
            "total": len(census),
            "covered": len(census) - len(missing),
            "missing_models": missing,
        }
    return rollup


def verify_rollup(rollup: dict[str, Any]) -> list[str]:
    """Recompute the chain; return the list of failures (empty == intact)."""
    problems: list[str] = []
    if rollup.get("schema") != ROLLUP_SCHEMA:
        return [f"unexpected schema {rollup.get('schema')!r}"]
    link = GENESIS
    seen: set[str] = set()
    for model in rollup.get("models", []):
        mid = model.get("model_id")
        if mid in seen:
            problems.append(f"duplicate model_id {mid!r}")
        seen.add(mid)
        body = {k: v for k, v in model.items() if k not in ("link", "entry_digest")}
        entry_digest = digest_object(body)
        if entry_digest != model.get("entry_digest", None):
            problems.append(f"{mid}: entry digest mismatch")
        link = _chain_step(link, entry_digest)
        if link != model.get("link"):
            problems.append(f"{mid}: chain link mismatch")
    if link != rollup.get("chain_root"):
        problems.append("chain root mismatch")
    return problems


def rollup_regressions(previous: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Monotone-burn-down violations: COMPLETE -> PARTIAL/gone, digest change."""
    problems: list[str] = []
    prev_models = {m["model_id"]: m for m in previous.get("models", [])}
    cur_models = {m["model_id"]: m for m in current.get("models", [])}
    for mid, prev in prev_models.items():
        cur = cur_models.get(mid)
        if cur is None:
            problems.append(f"{mid}: present before, gone now")
            continue
        if prev["status"] == "COMPLETE" and cur["status"] != "COMPLETE":
            problems.append(f"{mid}: COMPLETE -> {cur['status']}")
        for name, prev_digest in prev.get("artifacts", {}).items():
            if cur.get("artifacts", {}).get(name) != prev_digest:
                problems.append(f"{mid}: artifact bytes changed ({name})")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="receipts-rollup")
    parser.add_argument("bundles_root", help="directory of per-model bundle dirs")
    parser.add_argument("--census", help="JSON list of model ids expected to exist")
    parser.add_argument("--previous", help="previous roll-up JSON for regression gate")
    parser.add_argument("--out", help="write canonical roll-up JSON here (default stdout)")
    args = parser.parse_args(argv)

    census: list[str] | None = None
    if args.census:
        census = json.loads(Path(args.census).read_text(encoding="utf-8"))
        if not isinstance(census, list):
            print("--census must be a JSON list of model ids", file=sys.stderr)
            return 2

    rollup = build_rollup(Path(args.bundles_root), census=census)

    problems = verify_rollup(rollup)
    if args.previous:
        previous = json.loads(Path(args.previous).read_text(encoding="utf-8"))
        problems.extend(rollup_regressions(previous, rollup))

    body = canonical_bytes(rollup)
    if args.out:
        Path(args.out).write_bytes(body + b"\n")
    else:
        sys.stdout.buffer.write(body + b"\n")

    if problems:
        for p in problems:
            print(f"REGRESSION: {p}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
