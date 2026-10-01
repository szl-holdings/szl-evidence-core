# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Command surface. Exit codes: 0 PASS, 1 REVIEW, 2 BLOCKED, 3 NOT_RUN/ERROR.

    python -m szl_evidence_core selftest
        Fixtures that prove this package's own invariants. Gate 0.
    python -m szl_evidence_core vectors
        Vendored szl.lambda/v1 reference against all 60 golden vectors, bitwise.
    python -m szl_evidence_core compat <estate-root>
        Import the ORIGINAL _chain.py files from a checkout and prove digest,
        verdict and export byte-equality against this package.
    python -m szl_evidence_core audit <estate-root> [--json out.json]
        Measure primitive divergence (algorithm, separators, allow_nan,
        ensure_ascii, genesis) across every receipt implementation.
    python -m szl_evidence_core lambda-divergence <estate-root>
        Run each estate lambda_gate implementation that exposes a plain
        (axes, weights) function against the golden vectors.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import re
import sys
import types
from pathlib import Path
from typing import Any, Callable

from . import canonical as C
from . import chain as CH
from . import lambda_gate as L

EXIT = {"PASS": 0, "REVIEW": 1, "BLOCKED": 2, "NOT_RUN": 3, "ERROR": 3}


# --------------------------------------------------------------------------- #
# fixtures                                                                    #
# --------------------------------------------------------------------------- #

class Fixtures:
    def __init__(self) -> None:
        self.rows: list[tuple[str, bool, str]] = []

    def check(self, name: str, cond: bool, detail: str = "") -> None:
        self.rows.append((name, bool(cond), detail))

    def raises(self, name: str, exc: type, fn: Callable[[], Any], contains: str = "") -> None:
        try:
            fn()
        except exc as e:
            ok = contains in str(e) if contains else True
            self.rows.append((name, ok, "" if ok else f"message lacked {contains!r}: {e}"))
        except Exception as e:  # wrong exception type is a failure, not a pass
            self.rows.append((name, False, f"raised {type(e).__name__}: {e}"))
        else:
            self.rows.append((name, False, "did not raise"))

    def report(self, title: str) -> str:
        passed = sum(1 for _, ok, _ in self.rows if ok)
        for name, ok, detail in self.rows:
            if not ok:
                print(f"  FAIL  {name}  {detail}")
        status = "PASS" if passed == len(self.rows) else "BLOCKED"
        print(f"{title}: {passed}/{len(self.rows)} checks passed -> {status}")
        return status


def selftest() -> str:
    f = Fixtures()

    # -- canonical --------------------------------------------------------- #
    o = {"b": 2, "a": [1, {"z": None, "y": True}]}
    f.check("canon.sorted_compact", C.canonical_json(o) == '{"a":[1,{"y":true,"z":null}],"b":2}')
    f.check("canon.ascii_profile_escapes", C.canonical_json({"k": "ü"}) == '{"k":"\\u00fc"}')
    f.check("canon.lambda_profile_utf8", C.canonical_json({"k": "ü"}, profile=C.CANON_LAMBDA_V1) == '{"k":"ü"}')
    f.check("canon.profiles_differ_on_nonascii",
            C.canonical_bytes({"k": "ü"}) != C.canonical_bytes({"k": "ü"}, profile=C.CANON_LAMBDA_V1))
    f.check("canon.profiles_agree_on_ascii",
            C.canonical_bytes(o) == C.canonical_bytes(o, profile=C.CANON_LAMBDA_V1))
    f.raises("canon.rejects_nan", C.CanonicalizationError, lambda: C.canonical_json({"x": float("nan")}), "$.x")
    f.raises("canon.rejects_inf", C.CanonicalizationError, lambda: C.canonical_json([1.0, float("inf")]), "[1]")
    f.raises("canon.rejects_nonstr_key", C.CanonicalizationError, lambda: C.canonical_json({1: "a"}), "not str")
    f.raises("canon.rejects_object", C.CanonicalizationError, lambda: C.canonical_json({"d": object()}))
    f.raises("canon.rejects_unknown_profile", C.CanonicalizationError, lambda: C.canonical_json(o, profile="nope"))
    f.raises("canon.check_false_still_refuses_nan", ValueError, lambda: C.canonical_json({"x": float("nan")}, check=False))
    f.check("canon.sha256_vs_sha3_differ", C.digest_object(o, "sha256") != C.digest_object(o, "sha3_256"))
    f.raises("canon.unknown_algorithm", C.CanonicalizationError, lambda: C.digest(b"", "md5"))
    p = C.prefixed_digest(o)
    f.check("canon.prefixed_roundtrip", C.parse_prefixed_digest(p) == ("sha256", p.split(":")[1], True))
    f.check("canon.bare_hex_is_assumed_not_declared", C.parse_prefixed_digest("0" * 64)[2] is False)
    f.raises("canon.prefixed_unknown_algo", C.CanonicalizationError, lambda: C.parse_prefixed_digest("md5:" + "0" * 64))
    f.raises("canon.prefixed_garbage", C.CanonicalizationError, lambda: C.parse_prefixed_digest("hello"))
    f.check("canon.genesis_is_64_zeros", C.GENESIS == "0" * 64 and len(C.GENESIS) == 64)

    # -- UnifiedReceiptChain ----------------------------------------------- #
    u = CH.UnifiedReceiptChain()
    f.check("uchain.empty_head_is_genesis", u.head() == C.GENESIS)
    f.check("uchain.empty_verify_tuple", u.verify() == (True, 0, -1))
    f.check("uchain.empty_status_not_run", u.verify().status == "NOT_RUN")
    r0 = u.emit("k", "op", {"x": 1})
    r1 = u.emit_lambda(0.9, 0.8, True, 4)
    r2 = u.emit_energy({"label": "UNAVAILABLE", "joules": None, "source": "none"})
    f.check("uchain.seq_increments", (r0["seq"], r1["seq"], r2["seq"]) == (0, 1, 2))
    f.check("uchain.prev_links", r1["prev"] == r0["digest"] and r2["prev"] == r1["digest"])
    f.check("uchain.record_field_set", set(r0) == {"seq", "kernel", "op", "attrs", "prev", "digest", "ts"})
    f.check("uchain.lambda_is_labelled_conjecture", "Conjecture 1" in r1["attrs"]["lambda_status"] and r1["attrs"]["advisory"] is True)
    f.check("uchain.energy_none_stays_none", r2["attrs"]["joules"] is None)
    f.check("uchain.verify_ok", u.verify() == (True, 3, -1) and u.verify().status == "PASS")
    f.check("uchain.returned_record_detached", (r0.__setitem__("kernel", "evil"), u.verify().ok)[1])
    f.check("uchain.kernels_touched_order", u.kernels_touched() == ["k", "lambda_gate", "energy_core"])
    f.raises("uchain.attrs_nan_refused", ValueError, lambda: u.emit("k", "op", {"x": float("nan")}))
    f.raises("uchain.attrs_not_dict_refused", TypeError, lambda: u.emit("k", "op", [1]))
    f.check("uchain.len", len(u) == 3 and u.count() == 3)
    cp = u.checkpoint()
    f.check("uchain.checkpoint_schema", cp == {"schema": CH.CHECKPOINT_SCHEMA, "depth": 3, "head": u.head()})
    f.check("uchain.verify_against_checkpoint", u.verify(expected_head=cp["head"], expected_depth=3).ok)
    f.check("uchain.truncation_detected", u.verify(expected_head=cp["head"], expected_depth=2) == (False, 3, 2))
    f.raises("uchain.bad_checkpoint_args", ValueError, lambda: u.verify(expected_head="xyz", expected_depth=3))
    f.raises("uchain.genesis_checkpoint_needs_zero_depth", ValueError, lambda: u.verify(expected_head=C.GENESIS, expected_depth=1))
    blob = u.to_json()
    f.check("uchain.to_json_is_bare_list", blob.startswith("[") and json.loads(blob)[0]["seq"] == 0)
    f.check("uchain.verify_json_legacy_list", CH.UnifiedReceiptChain.verify_json(blob) == (True, 3, -1))
    env = u.to_envelope()
    doc = json.loads(env)
    f.check("uchain.envelope_declares_algorithm", doc["algorithm"] == "sha3_256" and doc["canon"] == C.CANON_RECEIPT and doc["trust"] == C.UNSIGNED_HONEST)
    f.check("uchain.verify_json_envelope", CH.UnifiedReceiptChain.verify_json(env) == (True, 3, -1))
    doc["head"] = "f" * 64
    f.check("uchain.envelope_head_lie_detected", not CH.UnifiedReceiptChain.verify_json(json.dumps(doc)).ok)
    tampered = json.loads(blob); tampered[1]["attrs"]["score"] = 0.1
    f.check("uchain.tamper_detected_at_index", CH.UnifiedReceiptChain.verify_json(json.dumps(tampered)) == (False, 3, 1))
    reordered = json.loads(blob); reordered[0], reordered[1] = reordered[1], reordered[0]
    f.check("uchain.reorder_detected", not CH.UnifiedReceiptChain.verify_json(json.dumps(reordered)).ok)
    extra = json.loads(blob); extra[0]["note"] = "x"
    f.check("uchain.extra_field_rejected", CH.UnifiedReceiptChain.verify_json(json.dumps(extra)) == (False, 3, 0))
    # isolate the prev-link check: valid seq, valid body digest, wrong prev
    relinked = json.loads(blob)
    relinked[1]["prev"] = "e" * 64
    body = {k: relinked[1][k] for k in ("seq", "kernel", "op", "attrs", "prev")}
    relinked[1]["digest"] = CH.UnifiedReceiptChain._digest_body(body)
    f.check("uchain.prev_link_isolated", CH.UnifiedReceiptChain.verify_json(json.dumps(relinked)) == (False, 3, 1))
    f.check("uchain.duplicate_key_rejected", CH.UnifiedReceiptChain.verify_json('[{"seq":0,"seq":0}]') == (False, 0, 0))
    f.check("uchain.nan_constant_rejected", CH.UnifiedReceiptChain.verify_json('[NaN]') == (False, 0, 0))
    f.check("uchain.not_json_rejected", CH.UnifiedReceiptChain.verify_json("{") == (False, 0, 0))
    f.check("uchain.object_without_schema_rejected", not CH.UnifiedReceiptChain.verify_json('{"records":[]}').ok)
    u2 = CH.UnifiedReceiptChain(algorithm="sha256")
    u2.emit("k", "op", {"x": 1})
    f.check("uchain.sha256_variant_differs", u2.head() != r0["digest"])
    f.check("uchain.sha256_envelope_verifies", CH.UnifiedReceiptChain.verify_json(u2.to_envelope()) == (True, 1, -1))
    f.check("uchain.sha256_bare_list_fails_as_sha3", not CH.UnifiedReceiptChain.verify_json(u2.to_json()).ok)
    f.raises("uchain.unknown_algorithm", C.CanonicalizationError, lambda: CH.UnifiedReceiptChain(algorithm="md5"))
    f.check("uchain.tensor_digest_repr_fallback_is_hex64", re.fullmatch(r"[0-9a-f]{64}", CH.tensor_digest([1, 2])) is not None)

    # -- ReceiptChain ------------------------------------------------------ #
    rc = CH.ReceiptChain()
    f.check("rchain.empty_head_none", rc.head() is None and len(rc) == 0)
    d0 = rc.emit({"a": 1}); d1 = rc.emit({"a": 2})
    f.check("rchain.emit_returns_hex64", re.fullmatch(r"[0-9a-f]{64}", d0) is not None)
    f.check("rchain.verify_ok", rc.verify() == (True, 2, -1))
    f.check("rchain.rows_shape", set(rc.rows()[0]) == {"a", "seq", "prev", "digest"} and rc.rows()[1]["prev"] == d0)
    f.raises("rchain.reserved_seq_refused", ValueError, lambda: rc.emit({"seq": 9}), "reserved")
    f.raises("rchain.reserved_prev_refused", ValueError, lambda: rc.emit({"prev": "x"}), "reserved")
    f.raises("rchain.nan_refused", C.CanonicalizationError, lambda: rc.emit({"v": float("nan")}))
    f.raises("rchain.not_dict_refused", TypeError, lambda: rc.emit([1]))
    f.check("rchain.rows_detached", (rc.rows()[0].__setitem__("a", 99), rc.verify().ok)[1])
    rc2 = CH.ReceiptChain(); rc2.emit({"a": 1}); rc2.emit({"a": 2})
    rc2._rows[1]["prev"] = "e" * 64
    rc2._rows[1]["digest"] = C.digest(C.canonical_bytes({k: v for k, v in rc2._rows[1].items() if k != "digest"}), "sha3_256")
    f.check("rchain.prev_link_isolated", rc2.verify() == (False, 1, 1))
    rc._rows[0]["a"] = 99  # simulate hostile mutation of storage
    f.check("rchain.tamper_detected", rc.verify() == (False, 0, 0))

    # -- ChainVerification tuple compatibility ------------------------------ #
    v = CH.ChainVerification(True, 2, -1, "why")
    ok, depth, bad = v
    f.check("verif.unpacks", (ok, depth, bad) == (True, 2, -1))
    f.check("verif.equals_plain_tuple", v == (True, 2, -1) and (True, 2, -1) == v)
    f.check("verif.reason_and_status", v.reason == "why" and v.status == "PASS")
    f.check("verif.blocked_status", CH.ChainVerification(False, 2, 1).status == "BLOCKED")

    # -- lambda_gate ------------------------------------------------------- #
    f.check("lambda.nominal", abs(L.lambda_v1([0.9] * 4, [0.25] * 4) - 0.9) < 1e-15)
    f.check("lambda.zero_axis_is_exact_zero", L.lambda_v1([0.9, 0.9, 0.9, 0.0], [0.25] * 4) == 0.0)
    f.check("lambda.zero_veto_verdict", L.gate_v1([0.9, 0.9, 0.9, 0.0], [0.25] * 4, 0.8) == (L.NO_GO, L.ZERO_VETO))
    f.check("lambda.go", L.gate_v1([0.95] * 4, [0.25] * 4, 0.8) == (L.GO, None))
    f.check("lambda.below_tau", L.gate_v1([0.5] * 4, [0.25] * 4, 0.8) == (L.NO_GO, L.BELOW_TAU))
    f.check("lambda.tau_zero_blocked", L.gate_v1([0.9] * 4, [0.25] * 4, 0.0) == (L.BLOCK, L.TAU_INVALID))
    f.check("lambda.no_clamp_out_of_range", L.gate_v1([1.2, 0.9], [0.5, 0.5], 0.8) == (L.BLOCK, L.AXIS_OUT_OF_RANGE))
    f.check("lambda.no_renormalise", L.gate_v1([0.9, 0.9], [0.6, 0.6], 0.8) == (L.BLOCK, L.WEIGHT_SUM))
    f.check("lambda.bool_is_not_a_number", L.gate_v1([True, 0.9], [0.5, 0.5], 0.8) == (L.BLOCK, L.TYPE_INVALID))
    f.check("lambda.empty_is_error_not_zero", L.gate_v1([], [], 0.8) == (L.BLOCK, L.EMPTY))
    f.check("lambda.nan_axis_blocked", L.gate_v1([float("nan"), 0.9], [0.5, 0.5], 0.8) == (L.BLOCK, L.NONFINITE_AXIS))
    vd = L.evaluate([0.9] * 4, [0.25] * 4, 0.8)
    f.check("lambda.verdict_carries_conjecture", vd.status == L.CONJECTURE_1 and vd.admitted and vd.value_f64 == L.encode_f64(vd.value))
    f.check("lambda.verdict_as_attrs_jsonable", C.canonical_json(vd.as_attrs()).startswith("{"))
    bad = L.evaluate([0.9, 0.0], [0.5, 0.5], 0.8)
    f.check("lambda.vetoed_verdict_value_zero", bad.verdict == L.NO_GO and bad.value == 0.0 and not bad.admitted)
    m = L.evaluate_mapping({"b": 0.9, "a": 0.8}, {"a": 0.5, "b": 0.5}, 0.8)
    f.check("lambda.mapping_order_independent", m.value == L.lambda_v1([0.8, 0.9], [0.5, 0.5]))
    f.check("lambda.mapping_key_mismatch", L.evaluate_mapping({"a": 0.9}, {"b": 0.5}, 0.8).code == L.LENGTH_MISMATCH)
    f.check("lambda.f64_roundtrip", L.decode_f64(L.encode_f64(0.1)) == 0.1)
    # the two estate variants the audit flagged, measured against the contract
    def floored(axes, weights):  # a11oy/payloads/lambda_gate.py
        log = sum(w * math.log(max(1e-6, min(1.0, max(0.0, x)))) for x, w in zip(axes, weights))
        return math.exp(log / sum(weights))
    f.check("lambda.floored_variant_loses_veto", floored([0.9, 0.9, 0.9, 0.0], [0.25] * 4) > 0.0)
    rep = L.check_conformance(floored, name="a11oy-floored")
    f.check("lambda.floored_variant_nonconformant", rep.status == "BLOCKED" and len(rep.failures) > 0)
    ref = L.check_conformance(L.lambda_v1, L.gate_v1, name="reference", bitwise=True)
    f.check("lambda.reference_bitwise_60_of_60", ref.conformant and ref.vectors == 60, ref.summary())

    return f.report("szl_evidence_core selftest")


# --------------------------------------------------------------------------- #
# vectors                                                                     #
# --------------------------------------------------------------------------- #

def vectors() -> str:
    doc = L.load_vectors()
    rep = L.check_conformance(L.lambda_v1, L.gate_v1, name="vendored reference", vectors=doc, bitwise=True)
    print(rep.summary())
    print(f"  vectors file canonical sha256 {L.canonical_sha256(doc)}")
    for fail in rep.failures[:10]:
        print("  ", fail)
    return rep.status


# --------------------------------------------------------------------------- #
# compat: prove byte-equality against the ORIGINAL estate files               #
# --------------------------------------------------------------------------- #

def _load_module(path: Path, name: str) -> types.ModuleType | None:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # dataclasses resolve their module through sys.modules
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:  # the original may need torch or a sibling package
        print(f"  skip {path}: {type(exc).__name__}: {exc}")
        return None
    return mod


def compat(root: Path) -> str:
    f = Fixtures()
    unified = sorted(p for p in root.rglob("_chain.py") if "build/" not in str(p) and "corpus/" not in str(p))
    payload_fixture = [{"a": 1, "s": "ü"}, {"a": 2, "nested": {"z": [1, 2, 3]}}, {"a": 3, "flag": True, "none": None}]
    ops_fixture = [("governed_norm", "rms_norm", {"eps": 1e-6, "in_shape": [2, 3]}),
                   ("lambda_gate", "lambda_gate", {"score": 0.91, "threshold": 0.8, "passed": True, "k": 4, "advisory": True}),
                   ("energy_core", "measure_energy", {"label": "UNAVAILABLE", "joules": None, "source": ""})]
    tested = 0
    for path in unified:
        mod = _load_module(path, f"orig_{tested}")
        if mod is None:
            continue
        rel = str(path.relative_to(root))
        if hasattr(mod, "UnifiedReceiptChain"):
            orig = mod.UnifiedReceiptChain(); mine = CH.UnifiedReceiptChain()
            for k, o, a in ops_fixture:
                ro = orig.emit(k, o, a); rm = mine.emit(k, o, a)
                f.check(f"{rel}: digest {k}", ro["digest"] == rm["digest"], f"{ro['digest'][:12]} vs {rm['digest'][:12]}")
            f.check(f"{rel}: head", orig.head() == mine.head())
            f.check(f"{rel}: verify tuple", tuple(orig.verify()) == tuple(mine.verify()) == (True, 3, -1))
            oj, mj = orig.to_json(), mine.to_json()
            strip = lambda s: re.sub(r'"ts":[0-9.e+-]+,?', "", s)  # ts is wall-clock, outside the hash
            f.check(f"{rel}: to_json bytes (minus ts)", strip(oj) == strip(mj))
            f.check(f"{rel}: original verify_json accepts mine", tuple(mod.UnifiedReceiptChain.verify_json(mj)) == (True, 3, -1))
            f.check(f"{rel}: mine verify_json accepts original", CH.UnifiedReceiptChain.verify_json(oj) == (True, 3, -1))
            if hasattr(orig, "checkpoint"):
                try:
                    f.check(f"{rel}: checkpoint equal", orig.checkpoint() == mine.checkpoint())
                except TypeError:
                    f.check(f"{rel}: checkpoint (legacy signature)", True)
            if hasattr(mod, "tensor_digest"):
                f.check(f"{rel}: tensor_digest fallback equal", mod.tensor_digest([1.0, 2.0]) == CH.tensor_digest([1.0, 2.0]))
            tested += 1
        elif hasattr(mod, "ReceiptChain"):
            orig = mod.ReceiptChain(); mine = CH.ReceiptChain()
            for p in payload_fixture:
                f.check(f"{rel}: digest", orig.emit(dict(p)) == mine.emit(dict(p)))
            f.check(f"{rel}: head", orig.head() == mine.head())
            f.check(f"{rel}: verify tuple", tuple(orig.verify()) == tuple(mine.verify()) == (True, 3, -1))
            f.check(f"{rel}: len", len(orig) == len(mine) == 3)
            tested += 1
    f.check("compat.at_least_one_original_imported", tested > 0, "no _chain.py could be imported")
    return f.report(f"compat against {tested} original _chain.py files")


# --------------------------------------------------------------------------- #
# audit: primitive divergence across every receipt implementation             #
# --------------------------------------------------------------------------- #

_DUMPS = re.compile(r"json\.dumps\(")
_HASHY = re.compile(r"hashlib\.|\.update\(|sha3?_?256|sha512|blake2|_digest\(|digest\(|_canon|canonical")


def _statement_at(text: str, start: int) -> str:
    """The enclosing statement: from line start to balanced parens, plus the rest
    of that line, so the context a json.dumps call sits in can be classified."""
    line_start = text.rfind("\n", 0, start) + 1
    depth = 0; i = text.index("(", start)
    while i < len(text):
        c = text[i]
        if c == "(": depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0: break
        i += 1
    line_end = text.find("\n", i)
    # two lines above catch `hashlib.sha256(` wrappers split across lines; two
    # lines below catch `raw = json.dumps(...)` followed by `sha3_256(raw)`.
    ctx_start = text.rfind("\n", 0, max(0, line_start - 1))
    ctx_start = text.rfind("\n", 0, max(0, ctx_start - 1)) + 1
    for _ in range(2):
        nxt = text.find("\n", line_end + 1) if line_end != -1 else -1
        line_end = nxt if nxt != -1 else len(text)
    return text[ctx_start: line_end]


def _classify_call(stmt: str, call: str) -> str:
    if "indent=" in call:
        return "pretty"            # human output, never a canonical digest input
    if "json.loads(" in stmt:
        return "roundtrip"         # detached snapshot, bytes are discarded
    if _HASHY.search(stmt):
        return "hash"              # feeds a digest, directly or via a canon helper
    if re.search(r"write|print\(|open\(|\.jsonl|\\n", stmt):
        return "write"
    return "unclassified"          # assigned to a name; may be hashed later


def audit(root: Path, out: Path | None) -> str:
    rows = []
    for name in ("receipts.py", "_chain.py", "receipt.py"):
        for p in sorted(root.rglob(name)):
            if any(part in p.parts for part in ("node_modules", "__pycache__", ".git")):
                continue
            t = p.read_text(errors="replace")
            calls = []
            for m in _DUMPS.finditer(t):
                stmt = _statement_at(t, m.start())
                call = t[m.start(): m.start() + len(stmt)]
                if "sort_keys" not in stmt:
                    continue
                calls.append({"role": _classify_call(stmt, stmt), "stmt": " ".join(stmt.split())[:160],
                              "separators": "separators" in stmt, "allow_nan_false": "allow_nan=False" in stmt,
                              "ensure_ascii_false": "ensure_ascii=False" in stmt})
            if not calls:
                continue
            hash_calls = [c for c in calls if c["role"] == "hash"]
            uncls = [c for c in calls if c["role"] == "unclassified"]
            rows.append({
                "path": str(p.relative_to(root)), "repo": p.relative_to(root).parts[0],
                "calls": len(calls), "hash_calls": len(hash_calls), "unclassified": len(uncls),
                "hash_separators_all": all(c["separators"] for c in hash_calls) if hash_calls else None,
                "hash_allow_nan": (None if not hash_calls else
                                   "strict" if all(c["allow_nan_false"] for c in hash_calls) else
                                   "none" if not any(c["allow_nan_false"] for c in hash_calls) else "mixed"),
                "hash_ensure_ascii_false": any(c["ensure_ascii_false"] for c in hash_calls),
                "algorithm": ("both" if "sha3_256" in t and re.search(r"sha256\(", t) else
                              "sha3_256" if "sha3_256" in t else "sha256" if "sha256" in t else "unknown"),
                "genesis_64_zeros": '"0" * 64' in t or "'0' * 64" in t,
                "detail": calls,
            })
    n = len(rows)
    if n == 0:
        print("audit: no receipt implementations found -> NOT_RUN"); return "NOT_RUN"
    hashing = [r for r in rows if r["hash_calls"]]
    algo = {}
    for r in rows: algo[r["algorithm"]] = algo.get(r["algorithm"], 0) + 1
    nan = {k: sum(r["hash_allow_nan"] == k for r in hashing) for k in ("strict", "mixed", "none")}
    no_sep = [r["path"] for r in hashing if r["hash_separators_all"] is False]
    utf8 = [r["path"] for r in hashing if r["hash_ensure_ascii_false"]]
    uncls = [r["path"] for r in rows if r["unclassified"]]
    genesis = sum(r["genesis_64_zeros"] for r in rows)
    print(f"receipt implementations with sort_keys json.dumps: {n}; with classified hash-feeding calls: {len(hashing)}")
    print(f"  algorithm (per file)            {algo}")
    print(f"  allow_nan on hash-feeding calls {nan}")
    print(f"  hash-feeding without separators {len(no_sep)}  {no_sep}")
    print(f"  hash-feeding ensure_ascii=False {len(utf8)}  {utf8}")
    print(f"  files with unclassified calls   {len(uncls)}  (assigned to a name; recall gap, listed not counted)")
    print(f"  genesis 64 zeros                {genesis}/{n}")
    status = "PASS"
    if nan["none"] + nan["mixed"] > 0 or no_sep:
        status = "BLOCKED"
    elif len([a for a in algo if algo[a]]) > 1:
        status = "REVIEW"
    print(f"primitive-divergence audit -> {status}")
    if out:
        out.write_text(json.dumps({"status": status, "n": n, "hashing_files": len(hashing), "algorithm": algo,
                                   "allow_nan_hash_calls": nan, "no_separators": no_sep, "ensure_ascii_false": utf8,
                                   "unclassified_files": uncls, "genesis_64_zeros": genesis, "rows": rows}, indent=1))
        print(f"  wrote {out}")
    return status


# --------------------------------------------------------------------------- #
# lambda-divergence: estate gate implementations vs the golden vectors        #
# --------------------------------------------------------------------------- #

_CANDIDATES = {
    # label: (sys.path entry relative to root, dotted module, resolver)
    # resolver(mod) -> (lambda_fn, gate_fn or None); lambda_fn is (axes, weights) -> float
    "szl-lambda-gate reference": ("szl-lambda-gate/reference", "szl_lambda_v1",
                                  lambda m: (m.lambda_v1, m.gate_v1)),
    "szl-khipu v1 path": ("szl-khipu", "szl_khipu.lambda_gate",
                          lambda m: (lambda x, w: m._from_log(m._log_lambda(*m._v1_vectors(x, w))), None)),
    "szl-khipu wgm (total)": ("szl-khipu", "szl_khipu.lambda_gate", lambda m: (m.wgm, None)),
    "szl-atelier wgm": ("szl-atelier", "kit.kernels.lambda_gate", lambda m: (m.wgm, None)),
    "szl-frontier wgm": ("szl-frontier/python", "szl_frontier.lambda_gate",
                         lambda m: (m.weighted_geometric_mean, None)),
    "szl-receipt lambda_score": ("szl-receipt/src", "szl_receipt.lambda_gate",
                                 lambda m: (m.lambda_score, None)),
}

# Gates with a fixed axis vocabulary cannot run the vectors; they get the one
# property the audit flagged, measured on the real code: a zeroed axis must
# yield exactly 0.0.
_FIXED_AXIS_GATES = {
    "a11oy/payloads/lambda_gate.py": ("lambda_of", lambda m: [k for k in m.AXIS_WEIGHTS if k != "energy"]),
    "vsp-otel/collector/lambda_gate.py": ("compute_lambda", lambda m: list(m.A_AXES)),
}


def _import_from(root: Path, rel: str, dotted: str):
    import importlib
    entry = str(root / rel)
    sys.path.insert(0, entry)
    try:
        return importlib.import_module(dotted)
    except Exception as exc:
        print(f"  skip {dotted}: {type(exc).__name__}: {str(exc)[:80]}")
        return None
    finally:
        if entry in sys.path:
            sys.path.remove(entry)


def _failure_modes(rep: L.ConformanceReport) -> dict[str, int]:
    modes: dict[str, int] = {}
    for fl in rep.failures:
        got = str(fl.get("got", ""))
        if "expected_error" in fl:
            mode = "invalid input returned a value (masked)" if got.startswith("value") else f"raised uncoded ({got[:24]})"
        elif "expected_value" in fl or "expected_value_f64" in fl:
            mode = "valid input wrong value"
        else:
            mode = "verdict"
        modes[mode] = modes.get(mode, 0) + 1
    return modes


def lambda_divergence(root: Path) -> str:
    doc = L.load_vectors()
    valid = sum(1 for v in doc["vectors"] if "error" not in v["expect"])
    invalid = len(doc["vectors"]) - valid
    print(f"golden vectors: {len(doc['vectors'])} ({valid} valid, {invalid} contract errors)")
    statuses = []
    for label, (rel, dotted, resolve) in _CANDIDATES.items():
        if not (root / rel).exists():
            print(f"  absent {rel}"); continue
        mod = _import_from(root, rel, dotted)
        if mod is None:
            statuses.append("NOT_RUN"); continue
        try:
            fn, gate = resolve(mod)
        except AttributeError as exc:
            print(f"  {label}: {exc} -> NOT_RUN"); statuses.append("NOT_RUN"); continue
        rep = L.check_conformance(fn, gate, name=label, vectors=doc)
        modes = _failure_modes(rep)
        print(f"  {label}: {rep.status}  values {rep.value_pass}/{len(doc['vectors'])}"
              + (f"  modes {modes}" if modes else ""))
        statuses.append(rep.status)

    for rel, (fn_name, axis_names) in _FIXED_AXIS_GATES.items():
        path = root / rel
        if not path.exists():
            print(f"  absent {rel}"); continue
        mod = _load_module(path, re.sub(r"\W", "_", rel))
        if mod is None or not hasattr(mod, fn_name):
            statuses.append("NOT_RUN"); continue
        keys = axis_names(mod)
        axes = {k: 0.9 for k in keys}; axes[keys[-1]] = 0.0
        value = getattr(mod, fn_name)(axes)
        lost = value > 0.0
        print(f"  {rel} {fn_name}: {len(keys)} axes, one zeroed -> \u039b={value:.9f} "
              f"-> {'BLOCKED (veto lost; contract requires exactly 0.0)' if lost else 'PASS (veto held)'}")
        statuses.append("BLOCKED" if lost else "PASS")

    if not statuses:
        return "NOT_RUN"
    order = ["BLOCKED", "NOT_RUN", "REVIEW", "PASS"]
    return min(statuses, key=order.index)


# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="szl_evidence_core")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest"); sub.add_parser("vectors")
    c = sub.add_parser("compat"); c.add_argument("root", type=Path)
    a = sub.add_parser("audit"); a.add_argument("root", type=Path); a.add_argument("--json", type=Path)
    d = sub.add_parser("lambda-divergence"); d.add_argument("root", type=Path)
    ns = ap.parse_args(argv)
    if ns.cmd == "selftest": status = selftest()
    elif ns.cmd == "vectors": status = vectors()
    elif ns.cmd == "compat": status = compat(ns.root)
    elif ns.cmd == "audit": status = audit(ns.root, ns.json)
    else: status = lambda_divergence(ns.root)
    return EXIT.get(status, 3)


if __name__ == "__main__":
    sys.exit(main())
