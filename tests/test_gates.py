"""pytest entry: the package's own gates are the test suite."""
import subprocess, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV = {"PYTHONPATH": str(ROOT / "src")}


def _run(*args):
    return subprocess.run([sys.executable, "-m", "szl_evidence_core", *args],
                          cwd=ROOT, env={**__import__("os").environ, **ENV},
                          capture_output=True, text=True)


def test_selftest_passes():
    r = _run("selftest")
    assert r.returncode == 0, r.stdout + r.stderr


def test_vectors_bitwise():
    r = _run("vectors")
    assert r.returncode == 0 and "60/60" in r.stdout, r.stdout + r.stderr
