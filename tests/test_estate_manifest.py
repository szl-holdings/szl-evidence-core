import copy
import unittest
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from szl_evidence_core.estate_manifest import admit, validate_manifest, validate_record

NOW = datetime(2026, 10, 27, 20, 0, tzinfo=timezone.utc)
SHA = "a" * 40
DIGEST = "b" * 64
SERVED = "c" * 64

def record(status="CONDITIONAL"):
    return {
        "id": "claim-f4",
        "kind": "claim",
        "name": "F4",
        "owner": "SZL Holdings",
        "scope": "proof",
        "status": status,
        "github": {
            "repository": "szl-holdings/szl-papers",
            "ref_type": "commit",
            "revision": SHA,
            "path": "MATH_RUNTIME_EXECUTION_MATRIX.md",
            "artifact_digest": DIGEST,
        },
        "hf": None,
        "domain": None,
        "verification": {
            "verifier_version": "estate-manifest/1",
            "workflow_run_ids": ["123"],
            "security_results": ["PASS"],
            "signer_identity": "test-signer",
            "signature_status": "VERIFIED",
            "freshness": "2026-10-27T19:00:00Z",
            "rollback_pointer": "receipt:previous",
        },
        "allowed_language": {
            "product": "advisory",
            "runtime": "advisory",
            "research": "conditional",
            "marketing": "do not claim proof",
        },
        "receipt": {
            "id": "receipt-1",
            "source_revision": SHA,
            "artifact_digest": DIGEST,
            "signer": "test-signer",
            "signature_status": "VERIFIED",
            "issued_at": "2026-10-27T19:00:00Z",
        },
    }

class EstateManifestTests(unittest.TestCase):
    def test_conditional_is_advisory(self):
        self.assertEqual(admit(record(), now=NOW).decision, "ADVISORY")

    def test_conjecture_fails_closed(self):
        self.assertEqual(admit(record("CONJECTURE"), now=NOW).decision, "DENY")

    def test_source_unbound_is_incomparable(self):
        self.assertEqual(admit(record("SOURCE_UNBOUND"), now=NOW).decision, "INCOMPARABLE")

    def test_branch_only_binding_is_not_admissible(self):
        item = record()
        item["github"]["ref_type"] = "branch"
        self.assertEqual(admit(item, now=NOW).decision, "DENY")

    def test_unsigned_receipt_is_denied(self):
        item = record()
        item["receipt"]["signature_status"] = "SKIPPED"
        self.assertEqual(admit(item, now=NOW).decision, "DENY")

    def test_stale_evidence_is_denied(self):
        item = record()
        item["verification"]["freshness"] = "2020-01-01T00:00:00Z"
        self.assertEqual(admit(item, now=NOW).decision, "DENY")

    def test_receipt_hash_link_is_required(self):
        item = record()
        item["receipt"]["source_revision"] = "d" * 40
        self.assertEqual(admit(item, now=NOW).decision, "DENY")

    def test_duplicate_record_ids_are_rejected(self):
        item = record()
        manifest = {
            "schema_version": "1.0.0",
            "manifest_id": "estate-1",
            "revision": SHA,
            "generated_at": "2026-10-27T19:00:00Z",
            "records": [item, copy.deepcopy(item)],
        }
        self.assertTrue(any("duplicate" in e for e in validate_manifest(manifest)))

    def test_hf_requires_source_pin_and_served_readback(self):
        item = record()
        item["hf"] = {
            "organization": "SZLHOLDINGS",
            "asset_type": "space",
            "name": "example",
            "revision": SHA,
            "artifact_digest": DIGEST,
            "license": "Apache-2.0",
            "served_bytes_sha256": SERVED,
            "readback_at": "2026-10-27T19:00:00Z",
            "source_revision": "e" * 40,
        }
        self.assertEqual(admit(item, now=NOW).decision, "INCOMPARABLE")
        self.assertTrue(any("source revision" in e for e in admit(item, now=NOW).reasons))

    def test_runtime_requires_rollback_pointer(self):
        item = record()
        item["kind"] = "runtime"
        item["status"] = "QUALIFIED"
        item["verification"]["rollback_pointer"] = ""
        self.assertTrue(any("rollback_pointer" in e for e in validate_record(item)))

if __name__ == "__main__":
    unittest.main()

