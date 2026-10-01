# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Λ, the weighted geometric mean, as the one shared primitive under seven gates.

What the audit found. Seven ``lambda_gate.py`` files exist in the estate and no
two share an API: 0 of 21 pairs score above 0.6 Jaccard. They are different
*gates* (a span exporter, a PINN solve router, a receipt aggregator, a YUYAY
vector gate) and must not be merged. What they share is one line of
mathematics, and that one line disagrees across copies:

  * ``a11oy/payloads/lambda_gate.py`` floors each axis at ``1e-6`` and divides
    by the weight sum. With one axis fully zeroed over four equal weights it
    returns Λ = 0.029220112 where the contract requires exactly 0.0. The veto
    is lost. It is latent today (0.029 is far below any admit threshold) and it
    is still wrong, because non-compensatory is the whole point of Λ.
  * ``vsp-otel`` clamps into [0, 1]; the contract says a value outside [0, 1]
    is an error, never silently repaired.
  * ``szl-atelier`` and ``szl-khipu`` conform, with weight tolerances of
    ``1e-9`` and ``1e-12`` respectively; the contract pins ``1e-12``.

The fix is not a new implementation. The estate already has a formal contract
with a stdlib reference and 60 golden vectors:

    szl-holdings/szl-lambda-gate  spec/szl.lambda.v1.json
                                  reference/szl_lambda_v1.py
    commit fad931134338d05136e522af48e003f4a4a57988
    reference blob 8396d8bee64f8aa4431e215dba203eae25225fc2
    reference sha256 57b264fa96056d1f2d77b797ba80eab087a729283f16416196fdd1423c9c532f

That reference is vendored byte-for-byte in ``_vendor/szl_lambda_v1.py`` and
re-exported here unchanged. This module adds only what the seven gates need in
order to call it: a mapping adaptor, a receipt-embeddable verdict that carries
the Conjecture 1 label, and a conformance checker so each gate's owner can
measure their current implementation against the vectors before switching.

Five repositories vendor the vector file pinned at commit d3443b05 with 50
vectors; upstream has since added 10 ``precedence_zero_does_not_mask_*``
vectors. The vendored copies are honest to their pin and stale, not corrupt.

Λ is advisory. Λ uniqueness is Conjecture 1 (open) and nothing here depends on
it; a GO verdict is a policy admit, not a proof.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence, Tuple

from ._vendor.szl_lambda_v1 import (  # noqa: F401  (re-exported, unchanged)
    ABSTAIN,
    AXIS_OUT_OF_RANGE,
    BELOW_TAU,
    BLOCK,
    EMPTY,
    ERROR_CODES,
    GO,
    LENGTH_MISMATCH,
    NONFINITE_AXIS,
    NONFINITE_WEIGHT,
    NO_GO,
    NUMERIC_TIE,
    SCHEMA,
    TAU_INVALID,
    TIE_EPS,
    TYPE_INVALID,
    VERDICTS,
    WEIGHT_NONPOSITIVE,
    WEIGHT_SUM,
    WEIGHT_SUM_TOL,
    ZERO_VETO,
    LambdaV1Error,
    canonical_json_bytes,
    canonical_sha256,
    decode_f64,
    encode_f64,
    gate_v1,
    lambda_v1,
    log_lambda_v1,
)

__all__ = [
    "SCHEMA", "WEIGHT_SUM_TOL", "TIE_EPS", "ERROR_CODES", "VERDICTS",
    "GO", "NO_GO", "ABSTAIN", "BLOCK", "ZERO_VETO", "BELOW_TAU", "NUMERIC_TIE",
    "LambdaV1Error", "lambda_v1", "log_lambda_v1", "gate_v1",
    "encode_f64", "decode_f64", "canonical_json_bytes", "canonical_sha256",
    "CONJECTURE_1", "LambdaVerdict", "evaluate", "evaluate_mapping",
    "ConformanceReport", "check_conformance", "load_vectors",
]

#: Stamped on every verdict. Λ uniqueness is an open conjecture; the gate is a
#: policy instrument and a GO must never be read as proven trust.
CONJECTURE_1 = "CONJECTURE_1_OPEN_ADVISORY"

_SPEC_DIR = Path(__file__).resolve().parent / "spec"


@dataclass(frozen=True)
class LambdaVerdict:
    """Receipt-embeddable outcome of one gate evaluation.

    ``value`` is None when Λ could not be computed (the verdict is then BLOCK
    with the error code). ``value_f64`` carries the exact bits so two organs
    can compare without re-deriving a float from decimal text.
    """

    verdict: str
    code: Optional[str]
    value: Optional[float]
    value_f64: Optional[str]
    tau: float
    axes: int
    schema: str = SCHEMA
    status: str = CONJECTURE_1

    @property
    def admitted(self) -> bool:
        return self.verdict == GO

    def as_attrs(self) -> dict[str, Any]:
        """Plain dict for ``UnifiedReceiptChain.emit`` or any JSON receipt."""
        return asdict(self)


def evaluate(axes: Sequence[float], weights: Sequence[float], tau: float) -> LambdaVerdict:
    """Gate a vector of axes. Never raises on bad input; it BLOCKs with the code."""
    verdict, code = gate_v1(list(axes), list(weights), tau)
    value: Optional[float] = None
    try:
        value = lambda_v1(list(axes), list(weights))
    except LambdaV1Error:
        value = None
    return LambdaVerdict(
        verdict=verdict, code=code, value=value,
        value_f64=None if value is None else encode_f64(value),
        tau=float(tau) if isinstance(tau, (int, float)) and not isinstance(tau, bool) else float("nan"),
        axes=len(axes) if isinstance(axes, (list, tuple)) else 0,
    )


def evaluate_mapping(axes: Mapping[str, float], weights: Mapping[str, float],
                     tau: float) -> LambdaVerdict:
    """Gate named axes. Keys are matched by name; a mismatch is LENGTH_MISMATCH.

    Most of the seven estate gates take ``{"a1": 0.9, ...}``. Sorting by key
    before the call makes the result independent of insertion order, which the
    contract's ``fsum`` then keeps bitwise stable.
    """
    if not isinstance(axes, Mapping) or not isinstance(weights, Mapping):
        return LambdaVerdict(BLOCK, TYPE_INVALID, None, None, float("nan"), 0)
    if set(axes) != set(weights):
        return LambdaVerdict(BLOCK, LENGTH_MISMATCH, None, None,
                             float(tau) if isinstance(tau, (int, float)) else float("nan"),
                             len(axes))
    names = sorted(axes)
    return evaluate([axes[n] for n in names], [weights[n] for n in names], tau)


# --------------------------------------------------------------------------- #
# Conformance: measure an implementation against the 60 golden vectors        #
# --------------------------------------------------------------------------- #

def load_vectors(path: Optional[Path] = None) -> dict[str, Any]:
    """Load the vendored upstream vector file and check its pinned digest."""
    path = path or (_SPEC_DIR / "lambda_v1_vectors.json")
    spec_path = path.parent / "szl.lambda.v1.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    if spec_path.exists():
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        pinned = spec.get("vectors", {}).get("sha256")
        actual = canonical_sha256(doc)
        if pinned and pinned != actual:
            raise LambdaV1Error(
                "VECTORS_DIGEST_MISMATCH",
                f"spec pins {pinned[:16]}..., file is {actual[:16]}...")
    return doc


def _decode(value: Any) -> Any:
    """Vector values: f64 strings decode; anything else passes through unchanged."""
    if isinstance(value, str) and value.startswith("f64:"):
        return decode_f64(value)
    if isinstance(value, list):
        return [_decode(v) for v in value]
    return value


@dataclass
class ConformanceReport:
    implementation: str
    vectors: int
    value_pass: int
    verdict_pass: int
    code_pass: int
    failures: list[dict[str, Any]]

    @property
    def conformant(self) -> bool:
        return not self.failures

    @property
    def status(self) -> str:
        if self.vectors == 0:
            return "NOT_RUN"
        return "PASS" if self.conformant else "BLOCKED"

    def summary(self) -> str:
        return (f"{self.implementation}: {self.status} "
                f"value {self.value_pass}/{self.vectors} "
                f"verdict {self.verdict_pass}/{self.vectors} "
                f"code {self.code_pass}/{self.vectors}")


def check_conformance(
    lambda_fn: Callable[[Any, Any], float],
    gate_fn: Optional[Callable[[Any, Any, Any], Tuple[str, Optional[str]]]] = None,
    *,
    name: str = "candidate",
    vectors: Optional[dict[str, Any]] = None,
    bitwise: bool = False,
) -> ConformanceReport:
    """Run an implementation against every golden vector.

    ``lambda_fn(axes, weights)`` must return Λ or raise an exception whose
    ``code`` attribute (or string form) names the contract error. ``gate_fn``
    is optional; when absent, verdicts are not scored. ``bitwise=True`` demands
    bit-identical values, as the contract requires of the reference itself;
    otherwise each vector's ``value_tol`` applies.

    This is the instrument each of the seven gate owners runs *before*
    repointing to the shared primitive, so the switch is a measured change and
    not a hopeful one.
    """
    doc = vectors or load_vectors()
    rows = doc["vectors"]
    value_pass = verdict_pass = code_pass = 0
    failures: list[dict[str, Any]] = []
    for row in rows:
        axes, weights = _decode(row["axes"]), _decode(row["weights"])
        expect = row["expect"]
        tol = float(row.get("value_tol", doc.get("value_tol", 1e-12)) or 0.0)
        failure: dict[str, Any] = {"id": row["id"]}

        # -- value / error code -------------------------------------------- #
        got_value: Optional[float] = None
        got_code: Optional[str] = None
        try:
            got_value = lambda_fn(axes, weights)
        except Exception as exc:  # the contract names the code; read it
            got_code = getattr(exc, "code", None) or str(exc).split(":")[0]
        if "error" in expect:
            if got_code == expect["error"]:
                value_pass += 1
                code_pass += 1
            else:
                failure["expected_error"] = expect["error"]
                failure["got"] = got_code if got_code else f"value {got_value!r}"
        else:
            want = decode_f64(expect["value_f64"])
            if got_value is None:
                failure["expected_value"] = want
                failure["got"] = f"error {got_code}"
            elif bitwise and encode_f64(got_value) != expect["value_f64"]:
                failure["expected_value_f64"] = expect["value_f64"]
                failure["got"] = encode_f64(got_value)
            elif not bitwise and not (abs(got_value - want) <= tol):
                failure["expected_value"] = want
                failure["got"] = got_value
                failure["tolerance"] = tol
            else:
                value_pass += 1
                code_pass += 1

        # -- gate verdict ---------------------------------------------------- #
        if gate_fn is not None and "verdict" in expect:
            tau = _decode(row.get("tau"))
            try:
                verdict, code = gate_fn(axes, weights, tau)
            except Exception as exc:
                verdict, code = f"RAISED {type(exc).__name__}", None
            if verdict == expect["verdict"] and code == expect.get("code"):
                verdict_pass += 1
            else:
                failure["expected_verdict"] = (expect["verdict"], expect.get("code"))
                failure["got_verdict"] = (verdict, code)
        elif gate_fn is None:
            verdict_pass += 1 if "verdict" not in expect else 0

        if len(failure) > 1:
            failures.append(failure)

    return ConformanceReport(
        implementation=name, vectors=len(rows), value_pass=value_pass,
        verdict_pass=verdict_pass, code_pass=code_pass, failures=failures)
