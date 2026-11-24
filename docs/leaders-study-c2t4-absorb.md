# Leader-Study Tranche-4 Absorb: AIR/COSE alignment (propose-only)

Lap: ouroboros tranche-4 leader study (Vibe dc lane, Kimi GO OURO-FRNT1-GOV-3fa2b8 attempt-2, order A,B,D,C; condition D = propose-only, no merges, no merges of this PR authorized).
Scope gate: public-surface study only. Every technique below carries a source and an applicability test. Unverifiable claims are marked unverified and NOT adopted. No code changes in this PR; text specs and conformance-vector definitions first, implementation via a separate governed PR.

## Leaders studied (cluster A: evidence, attestation, kernel-hub packages)

1. IETF RATS Attested Inference Receipt (AIR), COSE/CWT profile, drafts -00 to -02.
   - Sources: https://datatracker.ietf.org/doc/html/draft-tsyrulnikov-rats-attested-inference-receipt-00 ; https://datatracker.ietf.org/doc/html/draft-tsyrulnikov-rats-attested-inference-receipt/02/
   - Absorb action: align the szl-evidence-core receipt envelope to an AIR-shaped COSE/CWT profile WITHOUT weakening the deny-first verifier. Add negative conformance vectors per defect class (round-1 Aqta moat echo).
   - Applicability tests: (a) the verifier rejects every mutated receipt class; (b) AIR profile fields map one-to-one and every unmapped field fails closed.

2. IETF Enforcement Attestation Receipts for AI Inference Decisions.
   - Source: https://www.ietf.org/archive/id/draft-chueayen-attestation-receipts-02.html
   - Absorb action: cite the draft in capability-ledger docs as alignment evidence for the kill-switch-as-signed-entry design; capability-ledger verifier semantics unchanged (the never-GO gate stays).

3. Raucle Provenance Receipt v1.
   - Source: https://cloud.raucle.com/spec/provenance/v1/
   - Status: UNVERIFIED depth (product spec page only). Watch-only; not adopted.

## Proposed next steps (each gated, none executed in this PR)

- AIR/COSE profile mapping table for the existing receipt envelope (spec text).
- Negative conformance vector list per defect class: mutated signature, replayed nonce, orphaned fleet id, clock-skew abuse, unknown-field injection. All must fail closed in the deny-first verifier.
- Implementation PR via the device lane under a fresh Kimi GO after this study is absorbed.
