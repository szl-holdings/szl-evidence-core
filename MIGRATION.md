# Migration map: 43 files, three verdicts

Every file the audit flagged, with what happens to it. The verdicts are
measured, not stylistic. A file is **EXTRACT** only where this package proves
byte-identical behaviour against the original; **REPOINT PRIMITIVE** where the
module stays but its one shared line of math or canonicalisation moves here;
**DO NOT MERGE** where the audit shows different modules that happen to share a
filename.

Nothing below has been applied to a repository. Each row is one reviewable PR.

## `_chain.py` — CANONICAL + DRIFT GUARDS (11 files, 2 families) — PRs OPEN

Proven by `python -m szl_evidence_core compat <root>`: 53/53 checks across the
7 importable originals. Digests, `(ok, depth, first_break)` tuples, `to_json()`
bytes, `checkpoint()` dicts and each original's own `verify_json` accepting this
package's export all match.

**What the first attempt got wrong.** The plan was a guarded
`try: from szl_evidence_core.chain import …` in each kernel. szl-kernels' own
`test_hub_import_closure_is_complete_stdlib_and_torch_only` rejects that, and it
is right: these are Hugging Face kernel-hub artifacts that must load with no pip
packages, so they cannot import the shared package at runtime even behind a
guard. Two more of its tests (source-inspection of the chunked little-endian
digest, and loading `build/…/_chain.py` as a bare module) also break under a
shim. The shim was reverted before anything was pushed.

**What shipped instead.** This package is the canonical; every kernel keeps its
proven-identical copy; a `chain-drift-guard` workflow in each repo installs this
package pinned to a full commit SHA and runs `compat` on every change to
`_chain.py`. Drift fails the PR that caused it. Verified: a one-character change
to `GENESIS` or `separators` turns the guard BLOCKED.

| repo | family | PR | guard on GitHub runner |
|---|---|---|---|
| szl-kernels | Unified (source of truth) | [#47](https://github.com/szl-holdings/szl-kernels/pull/47) | SUCCESS (11/11) |
| szl-blocked | Unified (guarded → szl_kernels → vendored) | [#19](https://github.com/szl-holdings/szl-blocked/pull/19) | SUCCESS (10/10) |
| szl-provctl | Unified | [#13](https://github.com/szl-holdings/szl-provctl/pull/13) | SUCCESS (10/10) |
| szl-receipt-attn | Receipt | [#18](https://github.com/szl-holdings/szl-receipt-attn/pull/18) | SUCCESS (7/7) |
| szl-block-kv | Receipt | [#24](https://github.com/szl-holdings/szl-block-kv/pull/24) | SUCCESS (7/7) |
| szl-maskmod | Receipt | [#13](https://github.com/szl-holdings/szl-maskmod/pull/13) | SUCCESS (7/7) |
| YARQA-ATTN | Receipt | [#12](https://github.com/szl-holdings/YARQA-ATTN/pull/12) | SUCCESS (7/7) |

The 4 `build/` and `corpus/` copies are generated mirrors of the above and are
covered by each repo's existing mirror-equality test.

Non-hub consumers (services, payloads, collectors) can and should import
`szl_evidence_core.chain` directly; nothing in the hub contract applies to them.

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
| a11oy | `payloads/lambda_gate.py` | floored each axis at `1e-6` | **veto lost: Λ=0.023478339** → fixed to exactly 0.0 | **[PR #2411](https://github.com/szl-holdings/a11oy/pull/2411)** open, CI green (96 checks); non-vetoed values may move 1 ulp (fsum) |
| vsp-otel | `collector/lambda_gate.py` | floored at `1e-12`, clamped | **veto lost: Λ=0.003659266** → fixed to exactly 0.0, 3 tests added | **[PR #140](https://github.com/szl-holdings/vsp-otel/pull/140)** open, CI green (17 checks) |
| szl-receipt | `src/szl_receipt/lambda_gate.py` | `lambda_score` | NOT_RUN (needs `in_toto_attestation`) | run `lambda-divergence` in its own environment before switching |
| platform | `services/verticals/szl_pinn/_vendor/innovations/lambda_gate.py` | routes a PINN receipt through a gate; computes no Λ itself | n/a | import `gate_v1` for the verdict; no math to replace |

Both veto losses are latent today: 0.023 and 0.0037 sit far below any admit
threshold in use. They are still contract violations, because non-compensatory
is the entire point of Λ and a floor makes the aggregator compensatory by
construction.

Also measured: 5 repos vendored `lambda_v1_vectors.json` at 50 vectors pinned
to commit `d3443b05`; upstream has 60. The 10 new vectors are exactly the
`precedence_zero_does_not_mask_*` family that distinguishes a veto from an
invalid input. Re-vendored to `6a874e11` (PR #55), every port passes all 60
unchanged: [szl-khipu #84](https://github.com/szl-holdings/szl-khipu/pull/84),
[szl-formulas #17](https://github.com/szl-holdings/szl-formulas/pull/17),
[szl-receipt #46](https://github.com/szl-holdings/szl-receipt/pull/46),
[szl-typesafe-triage #50](https://github.com/szl-holdings/szl-typesafe-triage/pull/50);
szl-blocked's copy rides its drift-guard PR's follow-up.

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

## Status

Done (13 PRs open, all CI green, none merged): 7 drift guards, 2 veto fixes,
4 vector re-vendors. Merge order is free; nothing depends on anything else.

Remaining, each a separate decision rather than a mechanical PR:

1. `szl-atelier`, `szl-frontier` call `lambda_v1` so invalid input raises its
   code instead of reading as a veto (API change inside those modules; needs
   their owners' tests).
2. `szl-blocked` re-vendors its 60 vectors (its copy sits beside the chain).
3. `receipts.py` owners adopt `canonical_json` with a declared profile, one
   organ at a time, starting with the 7 UTF-8 hashers and `szl-gov`. Changing
   canonicalisation changes stored digests, so each needs its own migration note.
