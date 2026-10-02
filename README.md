# szl-evidence-core

The primitives under every SZL receipt, extracted once from 99 repositories.
Standard library only. No network, no signing, no claim beyond integrity.

```
python -m szl_evidence_core selftest                 # 122 fixtures, Gate 0
python -m szl_evidence_core vectors                  # szl.lambda/v1 reference, 60/60 bitwise
python -m szl_evidence_core compat <estate-root>     # byte-equality vs the ORIGINAL _chain.py files
python -m szl_evidence_core audit <estate-root>      # primitive divergence across 35 receipt files
python -m szl_evidence_core lambda-divergence <root> # 7 estate gates vs the golden vectors
```

Exit codes: 0 PASS, 1 REVIEW, 2 BLOCKED, 3 NOT_RUN/ERROR.

| module | what it is | provenance |
|---|---|---|
| `canonical` | two named canon profiles, algorithm-declared digests, fail-closed on NaN and non-string keys | new; numbers in its docstring come from `audit` |
| `chain` | `UnifiedReceiptChain`, `ReceiptChain`, `tensor_digest` | faithful port of szl-kernels `_chain.py` @ `c2b2fc8`; proven by `compat` |
| `lambda_gate` | `lambda_v1`, `gate_v1`, `evaluate_mapping`, `check_conformance` | szl-lambda-gate reference @ `fad9311` vendored byte-for-byte |
| `jcs` | RFC 8785 canonical JSON, third canon profile `CANON_JCS` | 20,012 doubles + 4,999 documents identical to the `rfc8785` reference |
| `merkle` | RFC 9162 tree hash, inclusion and consistency proofs; `UnifiedReceiptChain.checkpoint_v2` | 9/9 roots, 36/36 inclusion, 36/36 consistency vs transparency-dev vectors |

```python
from szl_evidence_core import UnifiedReceiptChain, evaluate_mapping

chain = UnifiedReceiptChain()                       # SHA3-256, 64-zero genesis, as the kernels
verdict = evaluate_mapping({"a1": .9, "a2": .9, "a3": .9, "a4": 0.0},
                           {"a1": .25, "a2": .25, "a3": .25, "a4": .25}, tau=0.8)
verdict.verdict, verdict.code, verdict.value        # ('NO_GO', 'ZERO_VETO', 0.0)  — exactly 0.0
chain.emit("lambda_gate", "gate", verdict.as_attrs())
chain.to_envelope()                                 # declares algorithm, canon, genesis, trust tier
```

What the audit measured, and this package fixes, is in `MIGRATION.md`. Who leads this
way of thinking and what we took from them is in `docs/FRONTIER.md`.
Evidence of every run is in `evidence/`.
