import hashlib
import json
import tempfile
import unittest

from szl_evidence_core.provenance import RECEIPT_SCHEMA, current_git_sha, emit_receipt


class ProvenanceReceiptTest(unittest.TestCase):
    def test_receipt_always_unverified(self):
        receipt = emit_receipt(artifact_data=b"x")
        self.assertIs(receipt["verified"], False)
        self.assertIn("UNVERIFIED", receipt["verification"])

    def test_cannot_forge_verified_kwarg(self):
        # Deliberate fail-closed test: "verified" is not a real parameter of
        # emit_receipt, so the call must raise TypeError. The kwarg is built
        # via a dict spread so static analyzers see no literal unsupported kwarg.
        forge_kwargs = {"verified": True}
        with self.assertRaises(TypeError):
            emit_receipt(**forge_kwargs)

    def test_schema_and_fields(self):
        zeros40 = "0" * 40
        receipt = emit_receipt(
            git_sha=zeros40,
            hf_revision="abc123",
            dataset_digest="d" * 64,
            kernel_id="kernel-1",
            artifact_data=b"payload",
        )
        self.assertEqual(receipt["schema"], RECEIPT_SCHEMA)
        self.assertEqual(receipt["git_sha"], zeros40)
        self.assertEqual(receipt["hf_revision"], "abc123")
        self.assertEqual(receipt["artifact_digest"], hashlib.sha256(b"payload").hexdigest())
        self.assertTrue(receipt["generated"])

    def test_git_sha_honest_outside_repo(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(current_git_sha(td))

    def test_json_roundtrip_stays_unverified(self):
        receipt = emit_receipt(artifact_data=b"x")
        self.assertFalse(json.loads(json.dumps(receipt))["verified"])


if __name__ == "__main__":
    unittest.main()