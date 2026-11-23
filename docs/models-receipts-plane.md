# Models-receipts plane (ou30)

Pure-Python (stdlib-only, huggingface_hub client only) toolchain giving every HF org SZLHOLDINGS public model a measured receipts-showcase posture, fail-closed, never faking green.

## Why
Owner directive: every model must fully showcase the right receipts. Measured baseline (2026-11-22T23:08:16Z, 399 public models): 2 FULL_SHOWCASE, 26 SHOWCASE_SEED, 369 TEMPLATE_BASELINE, 2 THIN. This plane turns that into a signed org-wide index, per-model packages, per-model ledger-mined receipts, and a fail-closed verifier.

## Tools
- scan.py - read-only full estate scan (HF API + per-model README resolve; tier rubric FULL_SHOWCASE / SHOWCASE_SEED / TEMPLATE_BASELINE / THIN).
- build_index.py - builds ou30_models_receipts_index_v1.json (gap manifest, family counts, integrity sha256 over canonical models JSON) + per-model propose-only packages + manifest.
- verify.py - fail-closed verifier: index integrity recompute, snippet entry hashes, core coverage, tier recomputation. PASS/FAIL receipt, exit 0/3. Current state: PASS 399/399.
- mine_receipts.py - mines estate receipt-ledger datasets for per-model historical receipts (dataset, file, file_sha256, evidence line). Measured: 15 datasets, 937 files, 4270 receipt hits; 214 models LEDGER-MINED (122/133 core); manifests are filled only from real receipts, never invented.

## Current receipts
- Wave-logs package: SZLHOLDINGS/wave-logs mesh/2026-11-22/ouroboros/ou30-models-receipts-tranche1/ (commits 42265caec24297ad2f7c899fa91a6f13862b5725 + c43eb7bf6a938b0ec43f056b1d8e0f50c0a6972d + v2 commit), readback-verified.
- Quad council 2026-11-22: Kimi governing ADAPT (core-first, YAML receipts block, NOT_SCANNED state, salad pointer cards) + astra-o + claude community-rail advisory + sol61 community-rail advisory, all converged.
- Apply ruling 2026-11-23: 2-2 split (governing Kimi + Claude: NO_WAIT_FOR_SIGNATURE_MINT; Astra + Sol: GO_NOW) - governing prevails, PROPOSE_ONLY_UNSIGNED held; applier staged on device with append-only, backup-first, halt-on-desync (5pct) gates, a11oy-freeze skip.
- Label HONEST_PARTIAL until per-model ledger receipts are minted and reflected in a post-apply scan (governing Q3).

## Doctrine
fail-closed; never fake green; receipts for every action; honest UNKNOWN; no bandaids. GitHub is the source of truth; HF stays aligned via pure stdlib Python clients.
