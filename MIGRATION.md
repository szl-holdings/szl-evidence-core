# Migration map: 43 files, three verdicts

Every file the audit flagged, with what happens to it. The verdicts are
measured, not stylistic. A file is **EXTRACT** only where this package proves
byte-identical behaviour against the original; **REPOINT PRIMITIVE** where the
module stays but its one shared line of math or canonicalisation moves here;
**DO NOT MERGE** where the audit shows different modules that happen to share a
filename.

Nothing below has been applied to a repository. Each row is one reviewable PR.

## `_chain.py` — EXTRACT (11 files, 2 families)

Proven by `python -m szl_evidence_core compat <root>`: 53/53 checks across the
7 importable originals (4 build/corpus duplicates excluded as identical copies).
Digests, `(ok, depth, first_break)` tuples, `to_json()` bytes, `checkpoint()`
dicts and the original `verify_json` accepting this package's export all match.

| repo | file | family | action |
|---|---|---|---|
| szl-kernels | `torch-ext/szl_kernels/_chain.py` | Unified (source of truth) | `from szl_evidence_core.chain import UnifiedReceiptChain, tensor_digest, GENESIS`; delete the 373-line body |
| szl-kernels | `build/torch-universal/szl_kernels/_chain.py` | Unified | build artifact of the above; regenerate |
| szl-kernels | `corpus/kernels/build/torch-universal/szl_kernels/_chain.py` | Unified (266L, older) | build artifact; regenerate |
| szl-blocked | `torch-ext/szl_blocked/_chain.py` | Unified (guarded fallback) | replace the `try: from szl_kernels._chain` / vendored-copy block with the import above; the fallback it vendored becomes unnecessary |
| szl-blocked | `build/torch-universal/szl_blocked/_chain.py` | Unified | build artifact; regenerate |
| szl-provctl | `torch-ext/szl_provctl/_chain.py` | Unified (guarded fallback) | same as szl-blocked |
| szl-provctl | `build/torch-universal/szl_provctl/_chain.py` | Unified | build artifact; regenerate |
| szl-receipt-attn | `torch-ext/szl_receipt_attn/_chain.py` | Receipt (48L) | `from szl_evidence_core.chain import ReceiptChain, GENESIS` |
| szl-block-kv | `torch-ext/szl_block_kv/_chain.py` | Receipt (34L) | same |
| szl-maskmod | `torch-ext/szl_maskmod/_chain.py` | Receipt (35L) | same |
| YARQA-ATTN | `torch-ext/yarqa_attn/_chain.py` | Receipt (51L) | same; exported `sha3_hex` → `szl_evidence_core.digest(b, "sha3_256")` |

Behaviour that changes, deliberately: `ReceiptChain.emit` now raises on a
payload carrying `seq`, `prev` or `digest` (the originals silently overwrote;
6 call sites checked, none affected) and refuses NaN/Inf (3 of 4 originals did
not). Every valid payload hashes to the same bytes.

## `lambda_gate.py` — REPOINT PRIMITIVE (7 files, 7 APIs, 0 pairs > 0.6)

These are seven different gates and stay seven files. Each one's weighted
geometric mean is replaced by `szl_evidence_core.lambda_gate.lambda_v1` /
`gate_v1`, the szl.lambda/v1 reference vendored unchanged. Measured against the
60 golden vectors by `python -m szl_evidence_core lambda-divergence <root>`:

| repo | file | current math | vectors | action |
|---|---|---|---|---|
| szl-khipu | `szl_khipu/lambda_gate.py` | v1-conformant (`_v1_vectors` path) | **60/60** | import the reference instead of the private port; keep `wgm` as the documented total wrapper, now over `lambda_v1` |
| szl-atelier | `kit/kernels/lambda_gate.py` | `wgm` returns 0.0 for everything invalid | 25/60, 35 masked | replace `wgm` body with `lambda_v1`; invalid input must raise its code, not read as a veto |
| szl-frontier | `python/szl_frontier/lambda_gate.py` | `weighted_geometric_mean` raises `GateError` without a code; 10 inputs masked as 0.0 | 25/60 | call `lambda_v1`, wrap `LambdaV1Error` into `GateError(code=...)` |
| a11oy | `payloads/lambda_gate.py` | floors each axis at `1e-6`, divides by weight sum | **veto lost: Λ=0.023478339 with one axis zeroed** (measured on the real code) | replace `lambda_of` with `evaluate_mapping`; `AXIS_WEIGHTS` becomes the weights argument |
| vsp-otel | `collector/lambda_gate.py` | floors at `1e-12`, clamps to [0,1], equal weights over `A_AXES` | **veto lost: Λ=0.003659266 with one axis zeroed** (measured on the real code; the collector hot path) | replace `compute_lambda` with `evaluate_mapping` and uniform weights; a value outside [0,1] must BLOCK, not clamp |
| szl-receipt | `src/szl_receipt/lambda_gate.py` | `lambda_score` | NOT_RUN (needs `in_toto_attestation`) | run `lambda-divergence` in its own environment before switching |
| platform | `services/verticals/szl_pinn/_vendor/innovations/lambda_gate.py` | routes a PINN receipt through a gate; computes no Λ itself | n/a | import `gate_v1` for the verdict; no math to replace |

Both veto losses are latent today: 0.023 and 0.0037 sit far below any admit
threshold in use. They are still contract violations, because non-compensatory
is the entire point of Λ and a floor makes the aggregator compensatory by
construction.

Also measured: 5 repos vendor `lambda_v1_vectors.json` at 50 vectors pinned to
commit `d3443b05`; upstream has 60. The 10 new vectors are exactly the
`precedence_zero_does_not_mask_*` family that distinguishes a veto from an
invalid input, which is the failure mode above. Re-vendor from upstream.

## `receipts.py` — DO NOT MERGE (25 files, 22 API surfaces)

Median pairwise API Jaccard is 0.000; only three pairs exceed 0.6 and all
three are copies within one repo (szl-v14 dist, a11oy amaru sidecar) or one
template (quant-bench/retrieval-bench). These are a durability writer, a
collector, an issuer, a DSSE signer, a domain contract and a dozen chains that
share a filename and nothing else. Merging them would create the API drift the
audit set out to remove.

What they *do* share is the canonicalisation line, and that is where the
divergence lives. `python -m szl_evidence_core audit <root>` over the 32 files
with hash-feeding `json.dumps`:

| primitive | measured | action |
|---|---|---|
| algorithm undeclared | 22 sha256 / 12 sha3_256 / 1 both | emit `prefixed_digest()` or an envelope; readers use `parse_prefixed_digest()` |
| `allow_nan` default | 21 of 32 never pass `allow_nan=False` | replace the local `json.dumps(...)` with `canonical_json()` |
| `ensure_ascii=False` | 7 files hash UTF-8, 25 hash ASCII-escaped | pick the profile explicitly: `profile=CANON_RECEIPT` or `CANON_UTF8`; declare it in the receipt |
| missing `separators` | 1 file: `szl-gov/tools/receipt.py` | `canonical_bytes()` |
| bespoke genesis | 15 of 35 | adopt `GENESIS`; a bespoke sentinel stays valid only if declared in the envelope |

Per-file rows with every classified call are in `evidence/primitive-audit.json`.
The classifier counts only calls it can tie to a digest (direct `hashlib`
wrapper, `.encode()` into a hash, or a `_canon`/`_digest` helper); 10 files
have further calls it could not classify and those are listed, not counted.

## Order

1. `szl-kernels` adopts `szl_evidence_core.chain` (one PR; everything else
   already prefers it through the guarded import).
2. `szl-blocked`, `szl-provctl` drop their vendored fallback (two PRs).
3. The four `ReceiptChain` kernels repoint (four PRs, mechanical).
4. `vsp-otel` and `a11oy/payloads` fix the veto (two PRs, with the
   `lambda-divergence` output before and after in the PR body).
5. `szl-atelier`, `szl-frontier` repoint the primitive; re-vendor the 60
   vectors in the five pinned repos.
6. `receipts.py` owners adopt `canonical_json` and a declared profile, one
   organ at a time, starting with the 7 UTF-8 hashers and `szl-gov`.
