"""Compatibility cannot be inferred from only the consumers that happened to run."""
from pathlib import Path
import os
import subprocess
import sys

import pytest

from szl_evidence_core.__main__ import compat, main


GOOD = "from szl_evidence_core.chain import ReceiptChain\n"


def consumer(root: Path, name: str, source: str = GOOD) -> str:
    path = root / name / "_chain.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path.relative_to(root).as_posix()


def test_complete_required_consumers_pass(tmp_path):
    required = [consumer(tmp_path, "first"), consumer(tmp_path, "second")]
    assert compat(tmp_path, required) == "PASS"


@pytest.mark.parametrize("source", [
    'raise ImportError("dependency unavailable")\n',
    "syntax error\n",
    "UNRELATED = True\n",
])
def test_one_good_consumer_cannot_hide_unchecked_consumer(tmp_path, source):
    consumer(tmp_path, "first")
    consumer(tmp_path, "second", source)
    assert compat(tmp_path) == "BLOCKED"


def test_missing_required_consumer_blocks(tmp_path):
    present = consumer(tmp_path, "present")
    assert compat(tmp_path, [present, "absent/_chain.py"]) == "BLOCKED"


def test_empty_estate_blocks(tmp_path):
    assert compat(tmp_path) == "BLOCKED"


def test_cli_missing_consumer_is_nonzero(tmp_path):
    consumer(tmp_path, "present")
    assert main(["compat", str(tmp_path), "--require-chain", "absent/_chain.py"]) == 2


def test_consumer_system_exit_zero_cannot_terminate_gate_successfully(tmp_path):
    consumer(tmp_path, "first")
    consumer(tmp_path, "second", "raise SystemExit(0)\n")
    repo = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "szl_evidence_core", "compat", str(tmp_path)],
        env={**os.environ, "PYTHONPATH": str(repo / "src")},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "BLOCKED" in result.stdout


def test_host_build_directory_does_not_hide_consumers(tmp_path):
    root = tmp_path / "build" / "estate"
    path = consumer(root, "present")
    assert compat(root, [path]) == "PASS"


def test_corpus_and_build_copies_are_excluded_but_cannot_satisfy_requirements(tmp_path):
    consumer(tmp_path, "present")
    ignored = consumer(tmp_path, "consumer/build", "syntax error\n")
    consumer(tmp_path, "consumer/corpus", "syntax error\n")
    assert compat(tmp_path) == "PASS"
    assert compat(tmp_path, [ignored]) == "BLOCKED"


def test_digest_mismatch_still_blocks(tmp_path):
    consumer(tmp_path, "different", GOOD + '''
class ReceiptChain(ReceiptChain):
    def emit(self, payload):
        super().emit(payload)
        return "0" * 64
''')
    assert compat(tmp_path) == "BLOCKED"
