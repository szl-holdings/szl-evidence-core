# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Adversarial tests for receipts_rollup (stdlib unittest, no network)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from szl_evidence_core import receipts_rollup as rr  # noqa: E402
from szl_evidence_core.canonical import canonical_bytes  # noqa: E402


def make_bundle(root: Path, model_id: str, *, drop=None, mutate_id=None):
    d = root / model_id
    d.mkdir(parents=True)
    eval_doc = {"harness": "szl-eval/1", "eval_sha256": "sha256:" + "a" * 64,
                "timestamp": "2026-11-25T00:00:00Z"}
    trace_doc = {"seed": 7, "prompt_sha256": "sha256:" + "b" * 64,
                 "completion_sha256": "sha256:" + "c" * 64}
    prov_doc = {"model_id": mutate_id or model_id, "base_weights": "Qwen3-4B",
                "dataset_revision": "rev-11", "mesh_job_id": "mesh-42"}
    (d / "eval.json").write_text(json.dumps(eval_doc), encoding="utf-8")
    (d / "trace.json").write_text(json.dumps(trace_doc), encoding="utf-8")
    (d / "provenance.json").write_text(json.dumps(prov_doc), encoding="utf-8")
    (d / "receipt.md").write_text(f"# receipt {model_id}\n", encoding="utf-8")
    if drop:
        (d / drop).unlink()
    return d


class RollupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bundles = self.root / "bundles"
        self.bundles.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_three_complete_and_deterministic(self):
        for mid in ("m-b", "m-a", "m-c"):
            make_bundle(self.bundles, mid)
        r1 = rr.build_rollup(self.bundles)
        self.assertEqual(r1["schema"], rr.ROLLUP_SCHEMA)
        self.assertEqual(r1["counts"], {"complete": 3, "partial": 0})
        self.assertTrue(r1["chain_root"].startswith("sha256:"))
        self.assertEqual([m["model_id"] for m in r1["models"]],
                         ["m-a", "m-b", "m-c"])
        r2 = rr.build_rollup(self.bundles)
        self.assertEqual(canonical_bytes(r1), canonical_bytes(r2))

    def test_missing_artifact_is_partial(self):
        make_bundle(self.bundles, "m-a", drop="trace.json")
        rollup = rr.build_rollup(self.bundles)
        self.assertEqual(rollup["counts"], {"complete": 0, "partial": 1})
        self.assertTrue(any("missing trace.json" in p
                            for p in rollup["models"][0]["problems"]))

    def test_provenance_id_mismatch_recorded(self):
        make_bundle(self.bundles, "m-a", mutate_id="m-zzz")
        rollup = rr.build_rollup(self.bundles)
        self.assertEqual(rollup["models"][0]["status"], "PARTIAL")
        self.assertTrue(any("model_id" in p and "!=" in p
                            for p in rollup["models"][0]["problems"]))

    def test_verify_detects_forged_entry(self):
        make_bundle(self.bundles, "m-a")
        rollup = rr.build_rollup(self.bundles)
        self.assertEqual(rr.verify_rollup(rollup), [])
        rollup["models"][0]["artifacts"]["eval.json"] = "sha256:" + "f" * 64
        problems = rr.verify_rollup(rollup)
        self.assertTrue(any("chain link mismatch" in p or "entry digest mismatch" in p
                            for p in problems))

    def test_verify_detects_chain_root_tamper(self):
        make_bundle(self.bundles, "m-a")
        rollup = rr.build_rollup(self.bundles)
        rollup["chain_root"] = "sha256:" + "0" * 64
        self.assertTrue(any("chain root mismatch" in p
                            for p in rr.verify_rollup(rollup)))

    def test_verify_detects_duplicate(self):
        make_bundle(self.bundles, "m-a")
        rollup = rr.build_rollup(self.bundles)
        rollup["models"].append(dict(rollup["models"][0]))
        self.assertTrue(any("duplicate" in p for p in rr.verify_rollup(rollup)))

    def test_census_coverage(self):
        make_bundle(self.bundles, "m-a")
        rollup = rr.build_rollup(self.bundles, census=["m-a", "m-b", "m-c"])
        self.assertEqual(rollup["census"]["total"], 3)
        self.assertEqual(rollup["census"]["covered"], 1)
        self.assertEqual(rollup["census"]["missing_models"], ["m-b", "m-c"])

    def test_regressions_complete_to_partial_and_digest_change(self):
        make_bundle(self.bundles, "m-a")
        make_bundle(self.bundles, "m-b", drop="receipt.md")
        prev = rr.build_rollup(self.bundles)
        # m-a bytes change, m-b heals (progress is fine)
        (self.bundles / "m-a" / "receipt.md").write_text("# changed\n", encoding="utf-8")
        (self.bundles / "m-b" / "receipt.md").write_text("# receipt m-b\n", encoding="utf-8")
        cur = rr.build_rollup(self.bundles)
        problems = rr.rollup_regressions(prev, cur)
        self.assertEqual(len(problems), 1)
        self.assertIn("m-a: artifact bytes changed (receipt.md)", problems[0])

        prev2 = rr.build_rollup(self.bundles)  # both complete now
        (self.bundles / "m-a" / "eval.json").unlink()
        cur2 = rr.build_rollup(self.bundles)
        problems2 = rr.rollup_regressions(prev2, cur2)
        self.assertTrue(any("COMPLETE -> PARTIAL" in p for p in problems2))

    def test_regression_when_model_gone(self):
        make_bundle(self.bundles, "m-a")
        prev = rr.build_rollup(self.bundles)
        rr.build_rollup(self.bundles)  # churn
        import shutil
        shutil.rmtree(self.bundles / "m-a")
        cur = rr.build_rollup(self.bundles)
        self.assertTrue(any("gone now" in p
                            for p in rr.rollup_regressions(prev, cur)))

    def test_cli_exit_codes(self):
        for mid in ("m-a", "m-b"):
            make_bundle(self.bundles, mid)
        census_path = self.root / "census.json"
        census_path.write_text(json.dumps(["m-a", "m-b", "m-c"]), encoding="utf-8")
        out_path = self.root / "rollup.json"
        rc = rr.main([str(self.bundles), "--census", str(census_path),
                      "--out", str(out_path)])
        self.assertEqual(rc, 0)
        saved = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(rr.verify_rollup(saved), [])
        # regression gate bites on digest change
        prev_path = self.root / "prev.json"
        prev_path.write_bytes(out_path.read_bytes())
        (self.bundles / "m-a" / "receipt.md").write_text("tamper\n", encoding="utf-8")
        rc2 = rr.main([str(self.bundles), "--census", str(census_path),
                       "--previous", str(prev_path), "--out", str(out_path)])
        self.assertEqual(rc2, 1)


if __name__ == "__main__":
    unittest.main()
