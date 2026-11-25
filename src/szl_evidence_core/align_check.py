# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Directory mount parity and model-card lint: the estate-port gate.

Why this module exists. The estate rule is "GitHub is the source, HF is the
mirror," but nothing in the primitives enforced that a *copy* of a tree
actually matches the tree it claims to mirror. The a11oy parity wall does
this for one repo inside Actions; the fleet needs the same fail-closed
comparison as a library, so any lane can check any GitHub worktree against
any exported HF directory (or two directories of anything) before
publishing, and CI can run it without network access.

Fail-closed rules, in the house style:

* A manifest is the sorted list of ``path`` -> ``sha256`` over regular files
  only (symlinks are flagged, never followed and never silently trusted).
* Two trees "align" only when both manifests exist, are parseable, share the
  same file set, and every digest matches. Anything else is a problem, and
  problems make the process exit non-zero. There is no "mostly aligned".
* Which paths are *expected* on each side is declared explicitly
  (``extra_a_ok`` / ``extra_b_ok``); nothing is excused implicitly, and an
  excused path is still digest-checked when it appears on both sides.
* The model-card lint is the same doctrine for metadata: required front
  matter keys must be present and non-empty when the card claims a model
  identity; a missing card is a finding, never a pass by absence.

Nothing here reads a network, a Hub API, or a token. Manifests are built
from local bytes; the caller harvests bytes. Claims are not upgraded:
"two local directories agree" is all this module ever says.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable

from .canonical import canonical_bytes, digest

__all__ = [
    "MANIFEST_SCHEMA",
    "CARD_LINT_SCHEMA",
    "build_manifest",
    "manifest_path_set",
    "align_manifests",
    "align_report",
    "lint_model_card",
    "main",
]

MANIFEST_SCHEMA = "szl.align-manifest/v1"
CARD_LINT_SCHEMA = "szl.card-lint/v1"
_CHUNK = 1 << 20


def build_manifest(root: Path, *, prefix: str = "") -> dict[str, Any]:
    """Deterministic ``path -> prefixed sha256`` manifest of a directory tree.

    Regular files only. Symlinks anywhere under ``root`` are recorded as
    problems rather than followed. Paths are POSIX-style and relative to
    ``root``, optionally under ``prefix`` so a subtree can be compared as a
    subtree on the other side.
    """
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(f"manifest root {root} is not a directory")
    files: dict[str, str] = {}
    links: list[str] = []
    stack = [root]
    while stack:
        cur = stack.pop()
        for entry in sorted(cur.iterdir()):
            rel = entry.relative_to(root).as_posix()
            if prefix:
                rel = prefix.rstrip("/") + "/" + rel
            if entry.is_symlink():
                links.append(rel)
            elif entry.is_dir():
                stack.append(entry)
            elif entry.is_file():
                h = hashlib.sha256()
                with entry.open("rb") as fh:
                    while True:
                        block = fh.read(_CHUNK)
                        if not block:
                            break
                        h.update(block)
                files[rel] = "sha256:" + h.hexdigest()
            # anything else (fifo, socket, broken): flagged via links path set
            elif not entry.exists():
                links.append(rel)
    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "files": dict(sorted(files.items())),
    }
    if links:
        manifest["symlinks_or_specials"] = sorted(set(links))
    return manifest


def manifest_path_set(manifest: dict[str, Any]) -> set[str]:
    return set(manifest.get("files", {}).keys())


def align_manifests(
    manifest_a: dict[str, Any],
    manifest_b: dict[str, Any],
    *,
    name_a: str = "a",
    name_b: str = "b",
    extra_a_ok: Iterable[str] = (),
    extra_b_ok: Iterable[str] = (),
) -> list[str]:
    """Fail-closed comparison of two manifests; [] means byte-aligned."""
    problems: list[str] = []
    if manifest_a.get("schema") != MANIFEST_SCHEMA:
        problems.append(f"{name_a}: unexpected schema {manifest_a.get('schema')!r}")
    if manifest_b.get("schema") != MANIFEST_SCHEMA:
        problems.append(f"{name_b}: unexpected schema {manifest_b.get('schema')!r}")
    if problems:
        return problems
    for name, manifest in ((name_a, manifest_a), (name_b, manifest_b)):
        for special in manifest.get("symlinks_or_specials", []):
            problems.append(f"{name}: symlink or special file refused: {special}")
    files_a = manifest_a.get("files", {})
    files_b = manifest_b.get("files", {})
    ok_a = set(extra_a_ok)
    ok_b = set(extra_b_ok)
    for path in sorted(set(files_a) - set(files_b)):
        if path not in ok_a:
            problems.append(f"only in {name_a}: {path}")
    for path in sorted(set(files_b) - set(files_a)):
        if path not in ok_b:
            problems.append(f"only in {name_b}: {path}")
    for path in sorted(set(files_a) & set(files_b)):
        if files_a[path] != files_b[path]:
            problems.append(f"digest mismatch: {path} ({files_a[path]} != {files_b[path]})")
    return problems


def align_report(
    manifest_a: dict[str, Any],
    manifest_b: dict[str, Any],
    **kw: Any,
) -> dict[str, Any]:
    """Problems plus a canonical report body for receipts."""
    problems = align_manifests(manifest_a, manifest_b, **kw)
    return {
        "schema": "szl.align-report/v1",
        "name_a": kw.get("name_a", "a"),
        "name_b": kw.get("name_b", "b"),
        "n_files_a": len(manifest_a.get("files", {})),
        "n_files_b": len(manifest_b.get("files", {})),
        "aligned": not problems,
        "problems": problems,
        "manifest_digest_a": "sha256:" + digest(canonical_bytes(manifest_a), "sha256"),
        "manifest_digest_b": "sha256:" + digest(canonical_bytes(manifest_b), "sha256"),
    }


_DST = {"base_model", "license", "pipeline_tag", "library_name", "tags"}


def lint_model_card(readme_text: str) -> dict[str, Any]:
    """Lint the YAML front matter of a model card. Findings, never passes-by-absence.

    Requires the card to open with a ``---`` front-matter block. Among the
    model-identity keys, ``license`` is mandatory (an unlabeled model card is
    a finding); ``base_model`` is mandatory for the fine-tune family, which
    is declared by the presence of any adapter/qlora/lora tag, never guessed.
    """
    findings: list[str] = []
    text = readme_text.lstrip("\ufeff")
    if not text.startswith("---") or text[3:4] not in ("\n", "\r"):
        return {
            "schema": CARD_LINT_SCHEMA,
            "ok": False,
            "findings": ["no YAML front matter at top of card"],
            "keys": {},
        }
    end = text.find("\n---", 3)
    if end < 0:
        return {
            "schema": CARD_LINT_SCHEMA,
            "ok": False,
            "findings": ["front matter not terminated"],
            "keys": {},
        }
    block = text[4:end]
    keys: dict[str, str] = {}
    for raw in block.splitlines():
        if ":" not in raw or raw.startswith((" ", "\t", "-")):
            continue
        k, _, v = raw.partition(":")
        k, v = k.strip(), v.strip()
        if k and v:
            keys[k] = v
    if "license" not in keys:
        findings.append("required key missing: license")
    derived = any(t in keys.get("tags", "") for t in ("qlora", "lora", "adapter"))
    if derived and "base_model" not in keys:
        findings.append("fine-tune family (lora/qlora/adapter tag) without base_model")
    return {
        "schema": CARD_LINT_SCHEMA,
        "ok": not findings,
        "findings": findings,
        "keys": keys,
    }


def _load_json(path: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected a JSON object at top level")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="align-check")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_manifest = sub.add_parser("manifest", help="write the manifest of a directory")
    p_manifest.add_argument("root")
    p_manifest.add_argument("--prefix", default="")
    p_manifest.add_argument("--out")

    p_align = sub.add_parser("align", help="compare two manifest JSON files")
    p_align.add_argument("manifest_a")
    p_align.add_argument("manifest_b")
    p_align.add_argument("--name-a", default="a")
    p_align.add_argument("--name-b", default="b")
    p_align.add_argument("--extra-a-ok", default="", help="comma-separated paths excused from side a only")
    p_align.add_argument("--extra-b-ok", default="")
    p_align.add_argument("--out")

    p_lint = sub.add_parser("lint-card", help="lint one model card README")
    p_lint.add_argument("readme")
    p_lint.add_argument("--out")

    args = parser.parse_args(argv)

    if args.cmd == "manifest":
        manifest = build_manifest(Path(args.root), prefix=args.prefix)
        body = canonical_bytes(manifest) + b"\n"
        if args.out:
            Path(args.out).write_bytes(body)
        else:
            sys.stdout.buffer.write(body)
        return 0

    if args.cmd == "align":
        report = align_report(
            _load_json(args.manifest_a), _load_json(args.manifest_b),
            name_a=args.name_a, name_b=args.name_b,
            extra_a_ok=[p for p in args.extra_a_ok.split(",") if p],
            extra_b_ok=[p for p in args.extra_b_ok.split(",") if p],
        )
        body = canonical_bytes(report) + b"\n"
        if args.out:
            Path(args.out).write_bytes(body)
        else:
            sys.stdout.buffer.write(body)
        if not report["aligned"]:
            for p in report["problems"]:
                print(f"ALIGNMENT: {p}", file=sys.stderr)
            return 1
        return 0

    # lint-card
    lint = lint_model_card(Path(args.readme).read_text(encoding="utf-8", errors="replace"))
    body = canonical_bytes(lint) + b"\n"
    if args.out:
        Path(args.out).write_bytes(body)
    else:
            sys.stdout.buffer.write(body)
    if not lint["ok"]:
        for f in lint["findings"]:
            print(f"CARD: {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
