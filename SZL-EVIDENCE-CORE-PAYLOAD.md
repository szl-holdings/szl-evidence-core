# SZL Evidence Core — extraction payload

Date 2026-10-01. Scope: the three filenames v7 named as the structural root of the
`killinchu#469` / `a11oy#2303` loop: `receipts.py` (25 copies), `_chain.py` (11),
`lambda_gate.py` (7). All 99 active repositories at the commits cloned for v7.
Every number below is produced by a command in this package and recorded in `evidence/`.

## The premise was wrong, and the measurement says so

v7 reported `receipts.py` as "23 variants across 24 copies, divergence 0.96" and I
instructed myself to extract it into a shared package. Before writing code I measured
API similarity between every pair of copies:

| file | copies | distinct API surfaces | pairs with Jaccard >= 0.6 | median Jaccard |
|---|---|---|---|---|
| `receipts.py` | 25 | 22 | 3 of 300 (all intra-repo or one template) | **0.000** |
| `lambda_gate.py` | 7 | 7 | **0 of 21** | 0.000 |
| `_chain.py` | 11 | 6 | **23 of 55** | 0.235 |

`receipts.py` is not one drifted module. It is a durability writer, a collector, a DSSE
signer, an issuer, a domain contract and a dozen chains that share a filename. Merging
them would have manufactured the API drift the exercise set out to remove. The
divergence metric in v7 measured text, not semantics, and that instrument needs the
Jaccard pre-check added before it reports "silent fork" again.

`_chain.py` is the one true extraction. What `receipts.py` and `lambda_gate.py` share is
the layer underneath, and that layer is where the real defects are.

## What shipped

`szl_evidence_core` — one package, standard library only, 1,677 lines, installs from a
wheel into a clean venv with no path tricks.

| module | content | proof |
|---|---|---|
| `canonical.py` | two named canon profiles (ASCII-escaped `szl.canon/v1`, UTF-8 `szl.lambda/v1`), algorithm-declared `prefixed_digest`, fail-closed on NaN/Inf and non-string keys | 18 fixtures |
| `chain.py` | `UnifiedReceiptChain` (7 copies) and `ReceiptChain` (4 copies), SHA3-256, 64-zero genesis, `szl.receipt-checkpoint/v1`, additive `to_envelope()` | **53/53 byte-equality checks against the 7 importable original files**: digests, verdict tuples, `to_json` bytes, checkpoints, and each original's own `verify_json` accepting this package's export |
| `lambda_gate.py` | szl-lambda-gate `reference/szl_lambda_v1.py` vendored byte-for-byte (blob `8396d8be`, commit `fad9311`), `evaluate_mapping`, `check_conformance` | **60/60 golden vectors, bitwise**, vector file canonical sha256 `61bfb041…` matching the spec's pin |

Gate 0: **90/90 fixtures**. Two mutation tests confirm the fixtures can fail: breaking
`separators` fails 3, disabling the prev-link check fails 1 (after I added the fixture
that isolates it — the first run had no fixture that distinguished a prev-link break
from a seq or digest break, which is a gap the mutation test exposed).

## Five measured findings on the real code

**1. Two production gates lose the Λ veto.** Non-compensatory is the whole point of Λ:
one zeroed axis must drive the result to exactly 0.0. Measured on the actual code, not a
reconstruction:

| gate | mechanism | one axis zeroed | contract |
|---|---|---|---|
| `a11oy/payloads/lambda_gate.py` `lambda_of` | floors each axis at `1e-6`, divides by weight sum | **Λ = 0.023478339** | 0.0 |
| `vsp-otel/collector/lambda_gate.py` `compute_lambda` | floors at `1e-12`, clamps to [0,1] | **Λ = 0.003659266** | 0.0 |

Both are latent: 0.023 and 0.0037 are far below any admit threshold in use. Both are
contract violations, and vsp-otel is the span-exporter hot path.

**2. Three gates mask invalid input as a veto.** Against 60 golden vectors (25 valid,
35 contract errors): `szl-khipu wgm`, `szl-atelier wgm` and `szl-frontier
weighted_geometric_mean` each get **25/60** — every valid value correct, every invalid
input returned as 0.0 or raised without the contract's code. A NaN axis and a vetoed
axis become indistinguishable downstream. `szl-khipu`'s internal `_v1_vectors` path is
**60/60** conformant; its public `wgm` is a documented total wrapper over it. The 10
vectors upstream added since the pin (`precedence_zero_does_not_mask_*`) test exactly
this failure, and five repos vendor the file at 50 vectors.

**3. The hash algorithm is never declared.** 22 receipt files hash SHA-256, 12 SHA3-256,
1 both, and no receipt body says which. A kernel ledger cannot be verified by a service
verifier. Fixed by `prefixed_digest()` and the envelope's `algorithm` field; the kernel
chains stay SHA3-256 so every ledger already written still verifies.

**4. Two canon profiles are live, not one.** Of 32 files whose `json.dumps` demonstrably
feeds a digest, **7 hash with `ensure_ascii=False`** (a11oy/amaru ×2, ayllu, quant-bench,
retrieval-bench, vertical-services, szl-nemo) and 25 with the ASCII default. The same
non-ASCII string hashes to two different digests across those groups today. My first pass
said "all 35 rely on the default" because it read only the first `json.dumps` per file;
the classifier was rewritten to tie each call to a digest and that claim was retracted.

**5. `allow_nan` is lax in 21 of 32 hash-feeding files.** The default emits bare `NaN`,
which is not JSON; a receipt containing it hashes locally and is unreadable by every
conforming verifier. One file (`szl-gov/tools/receipt.py`) also omits `separators`, so
its digests differ from every other organ's on whitespace alone.

## Commands

```
pip install szl_evidence_core-0.1.0-py3-none-any.whl
python -m szl_evidence_core selftest                     # 90/90 -> exit 0
python -m szl_evidence_core vectors                      # 60/60 bitwise -> exit 0
python -m szl_evidence_core compat   /path/to/estate     # 53/53 -> exit 0
python -m szl_evidence_core audit    /path/to/estate     # BLOCKED -> exit 2 (correct today)
python -m szl_evidence_core lambda-divergence /path/to/estate   # BLOCKED -> exit 2 (correct today)
```

The two BLOCKED exits are the estate's state, not the package's. They turn green as the
migration lands and they are the regression instruments that keep it green.

## Migration order (MIGRATION.md has the per-file rows)

1. `szl-kernels` adopts `szl_evidence_core.chain` — one PR; `szl-blocked` and `szl-provctl`
   already prefer it through a guarded import and drop their vendored fallbacks next.
2. Four `ReceiptChain` kernels repoint — mechanical.
3. `vsp-otel` and `a11oy/payloads` fix the veto — PR body carries the `lambda-divergence`
   output before and after.
4. `szl-atelier`, `szl-frontier` call `lambda_v1`; five repos re-vendor the 60 vectors.
5. `receipts.py` owners adopt `canonical_json` with an explicit profile, one organ at a
   time, starting with the 7 UTF-8 hashers and `szl-gov`. The 22 API surfaces stay where
   they are.

## Boundaries

Nothing is applied to any repository; every row is one reviewable PR. Hash chains are
UNSIGNED_HONEST: tamper-evident, not authenticated. Λ remains Conjecture 1 and every
verdict carries `CONJECTURE_1_OPEN_ADVISORY`. `szl-receipt/lambda_gate.py` is NOT_RUN
(needs `in_toto_attestation`); run `lambda-divergence` in its own environment before
switching. The audit classifier counts only calls it can tie to a digest; 10 files have
further calls it could not classify and those are listed in `evidence/primitive-audit.json`,
not counted.
