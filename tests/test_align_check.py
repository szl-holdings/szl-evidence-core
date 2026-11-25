# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Adversarial tests for align_check (stdlib unittest, no network)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from szl_evidence_core import align_check as ac  # noqa: E402


def make_tree(root: Path, files: dict, symlinks: dict | None = None):
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    for rel, target in (symlinks or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.symlink_to(target)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_manifest_deterministic_and_prefixed(self):
        a = self.root / "a"
        make_tree(a, {"x.txt": "1", "d/y.txt": "2"})
        m1 = ac.build_manifest(a)
        m2 = ac.build_manifest(a)
        self.assertEqual(m1["schema"], ac.MANIFEST_SCHEMA)
        self.assertEqual(m1["files"], m2["files"])
        self.assertEqual(list(m1["files"]), ["d/y.txt", "x.txt"])  # sorted
        m3 = ac.build_manifest(a, prefix="sub")
        self.assertEqual(sorted(m3["files"]), ["sub/d/y.txt", "sub/x.txt"])

    def test_symlink_flagged_not_followed(self):
        a = self.root / "a"
        make_tree(a, {"real.txt": "r"})
        (a / "link.txt").symlink_to("real.txt")
        m = ac.build_manifest(a)
        self.assertNotIn("link.txt", m["files"])
        self.assertEqual(m["symlinks_or_specials"], ["link.txt"])

    def test_align_clean_and_prefix_join(self):
        a, b = self.root / "a", self.root / "b"
        make_tree(a, {"README.md": "same", "src/x.py": "1"})
        make_tree(b, {"README.md": "same", "src/x.py": "1"})
        ma = ac.build_manifest(a)
        mb = ac.build_manifest(b)
        self.assertEqual(ac.align_manifests(ma, mb), [])
        # subtree-vs-whole with prefix must still align
        ma_sub = ac.build_manifest(a, prefix="pkg")
        mb_sub = ac.build_manifest(b, prefix="pkg")
        self.assertEqual(ac.align_manifests(ma_sub, mb_sub), [])
        self.assertIn("pkg/src/x.py", ma_sub["files"])

    def test_align_catches_digest_mismatch_and_missing_and_extra(self):
        a, b = self.root / "a", self.root / "b"
        make_tree(a, {"f.txt": "v1", "g.txt": "same", "a_only.txt": "x"})
        make_tree(b, {"f.txt": "v2", "g.txt": "same", "b_only.txt": "y"})
        problems = ac.align_manifests(ac.build_manifest(a), ac.build_manifest(b))
        self.assertEqual(len(problems), 3)
        self.assertTrue(any(p.startswith("digest mismatch: f.txt") for p in problems))
        self.assertIn("only in a: a_only.txt", problems)
        self.assertIn("only in b: b_only.txt", problems)

    def test_Excused_paths_still_digest_checked(self):
        a, b = self.root / "a", self.root / "b"
        make_tree(a, {"keep.txt": "1", "gen_a.txt": "one"})
        make_tree(b, {"keep.txt": "1", "gen_b.txt": "two"})
        problems = ac.align_manifests(
            ac.build_manifest(a), ac.build_manifest(b),
            extra_a_ok=["gen_a.txt"], extra_b_ok=["gen_b.txt"])
        self.assertEqual(problems, [])
        # excused but present on both sides with different bytes -> still bites
        make_tree(a, {"gen_a.txt": "CHANGED-TO-MATCH"})
        make_tree(b, {"gen_a.txt": "different"})
        problems2 = ac.align_manifests(
            ac.build_manifest(a), ac.build_manifest(b),
            extra_a_ok=["gen_a.txt"], extra_b_ok=["gen_b.txt", "gen_a.txt"])
        self.assertTrue(any("digest mismatch: gen_a.txt" in p for p in problems2))

    def test_align_symlink_on_one_side_is_a_problem(self):
        a, b = self.root / "a", self.root / "b"
        make_tree(a, {"f.txt": "1"})
        make_tree(b, {"f.txt": "1"}, symlinks={"z.txt": "f.txt"})
        problems = ac.align_manifests(ac.build_manifest(a), ac.build_manifest(b))
        self.assertTrue(any("symlink" in p for p in problems))

    def test_align_report_carries_manifest_digests(self):
        a, b = self.root / "a", self.root / "b"
        make_tree(a, {"f.txt": "1"})
        make_tree(b, {"f.txt": "1"})
        report = ac.align_report(ac.build_manifest(a), ac.build_manifest(b), name_a="gh", name_b="hf")
        self.assertTrue(report["aligned"])
        self.assertTrue(report["manifest_digest_a"].startswith("sha256:"))
        self.assertEqual(report["name_a"], "gh")


class CardLintTests(unittest.TestCase):
    def test_fine_tune_card_ok(self):
        card = "---\nlicense: apache-2.0\nbase_model: Qwen/Qwen2.5-1.5B-Instruct\ntags:\n  - qlora\n---\n# hi\n"
        lint = ac.lint_model_card(card)
        self.assertTrue(lint["ok"], lint)
        self.assertEqual(lint["findings"], [])

    def test_missing_license_is_finding(self):
        card = "---\nbase_model: Qwen/Qwen2.5-1.5B-Instruct\n---\n"
        lint = ac.lint_model_card(card)
        self.assertFalse(lint["ok"])
        self.assertEqual(lint["findings"], ["required key missing: license"])

    def test_lora_tag_without_base_model_is_finding(self):
        card = "---\nlicense: apache-2.0\ntags: adafruits lora\n---\n"
        lint = ac.lint_model_card(card)
        self.assertFalse(lint["ok"])
        self.assertTrue(any("base_model" in f for f in lint["findings"]))

    def test_no_front_matter_is_finding_not_pass(self):
        lint = ac.lint_model_card("# just markdown\n")
        self.assertFalse(lint["ok"])
        self.assertEqual(lint["findings"], ["no YAML front matter at top of card"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_cli_align_exit_codes(self):
        a, b = self.root / "a", self.root / "b"
        make_tree(a, {"f.txt": "1"})
        make_tree(b, {"f.txt": "1"})
        ma_path, mb_path = self.root / "ma.json", self.root / "mb.json"
        for d, out in ((a, ma_path), (b, mb_path)):
            rc = ac.main(["manifest", str(d), "--out", str(out)])
            self.assertEqual(rc, 0)
        report_path = self.root / "report.json"
        rc = ac.main(["align", str(ma_path), str(mb_path), "--out", str(report_path)])
        self.assertEqual(rc, 0)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertTrue(report["aligned"])
        # tamper one side -> exit 1 + problem recorded
        make_tree(b, {"f.txt": "different"})
        ac.main(["manifest", str(b), "--out", str(mb_path)])
        rc = ac.main(["align", str(ma_path), str(mb_path), "--out", str(report_path)])
        self.assertEqual(rc, 1)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertFalse(report["aligned"])
        self.assertTrue(any(p.startswith("digest mismatch: f.txt") for p in report["problems"]))

    def test_cli_lint_card_exit_codes(self):
        good = self.root / "good.md"
        good.write_text("---\nlicense: apache-2.0\n---\n# t\n", encoding="utf-8")
        self.assertEqual(ac.main(["lint-card", str(good)]), 0)
        bad = self.root / "bad.md"
        bad.write_text("# no front matter\n", encoding="utf-8")
        self.assertEqual(ac.main(["lint-card", str(bad)]), 1)


if __name__ == "__main__":
    unittest.main()
