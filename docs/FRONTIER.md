# Frontier study: who leads this way of thinking, and what we took

Date 2026-10-01. Scope: evidence-bound receipts, canonical bytes, append-only
logs, pre-action gates. The question was not "who is famous" but "whose
construction would a stranger's verifier accept". Every adoption below is
measured against the leader's own reference, not against our reading of it.

## The leaders

| who | what they fixed | the artifact that matters | status |
|---|---|---|---|
| **IETF SCITT** | one architecture for transparent supply-chain statements: sign a statement, register it with a transparency service, get a **receipt** that proves registration, attach it to make a **Transparent Statement** | [RFC 9943](https://datatracker.ietf.org/wg/scitt/documents/) "An Architecture for Trustworthy and Transparent Digital Supply Chains" | **Proposed Standard, 2026-06** |
| IETF SCITT (receipts) | the receipt format as COSE | [draft-ietf-scitt-receipts-ccf-profile-05](https://datatracker.ietf.org/wg/scitt/documents/) | 2026-09-23, waiting for AD go-ahead |
| IETF SCITT (local logs) | a Merkle-checkpointed **local** log, which is what every SZL `UnifiedReceiptChain` is | [draft-mih-scitt-checkpointed-local-log-01](https://datatracker.ietf.org/wg/scitt/documents/) | 2026-09-26 |
| IETF SCITT (agents) | a SCITT profile specifically for **AI-agent action receipts** | [draft-noa-scitt-ai-agent-receipt-01](https://datatracker.ietf.org/wg/scitt/documents/) | 2026-08-14, 97 pages |
| **Krausz, verification.\*** | pre-action **fail-closed gates for AI agent decisions**: a JWS receipt carrying canonical inputs, a derived binary act/halt gate, a versioned mapping id, a four-state vocabulary (verified / contradicted / indeterminate / not_evaluated), **reason codes that separate a state's substance from the verifier's own instrument failure**, and content-addressed `evidence_set` pinning | [draft-krausz-verification-state-03](https://datatracker.ietf.org/doc/draft-krausz-verification-state/) | individual draft, 2026-10-01 |
| **RFC 8785 JCS** | the one canonical JSON with an RFC number and independent implementations: ES2019 number serialisation, UTF-16 property sort, fixed escaping, `-0` → `0` | [RFC 8785 + errata](https://www.rfc-editor.org/rfc/inline-errata/rfc8785.html) | Informational, 2020 |
| **RFC 9162 / CT v2** | the Merkle Tree Hash with 0x00/0x01 domain separation, O(log n) inclusion proofs, consistency proofs that prove append-only | [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) | Experimental, widely deployed |
| **Sigstore Rekor v2** | tile-based transparency service; a **checkpoint is a signed Merkle root**, optionally with witness co-signatures; one entry type (`HashedRekord`), DSSE attestations reduced to a digest | [rekor-v2-spec](https://github.com/sigstore/architecture-docs/blob/main/rekor-v2-spec.md) | spec, 2026-05 |
| **transparency-dev Tessera** | successor to Trillian: tile-based logs with static, cacheable read APIs; the test vectors every CT/Rekor implementation is checked against | [tessera](https://github.com/transparency-dev/tessera), [merkle/testonly](https://github.com/transparency-dev/merkle) | active |
| **in-toto / DSSE** | the signing envelope under SLSA provenance: `payloadType`, base64 `payload`, `signatures[]`; PAE prevents cross-protocol confusion | [ITE-5](https://github.com/in-toto/ITE/blob/master/ITE/5/README.adoc) | stable |
| **SLSA v1.2** | what provenance must say and how it must be produced; Build L3 means a hardened, isolated builder; a Build Environment track is in draft | [build requirements](https://slsa.dev/spec/v1.2/build-requirements) | v1.2 |
| **C2PA 2.4** | content credentials as COSE_Sign1 with the credential in protected headers; the largest deployed "receipt attached to an artifact" system | [Content Credentials 2.4](https://spec.c2pa.org/specifications/specifications/2.4/specs/ContentCredentials.html) | 2.4 |

## What we had, honestly

Before this work the estate had 35 receipt implementations whose canonical
bytes were "whatever Python does", split across two undeclared profiles and
two undeclared hash algorithms; a hash chain whose checkpoint was `{depth,
head}`; a Λ gate whose veto had been floored away in two production paths; and
no proof shape a third party could verify without the whole ledger. All of it
UNSIGNED_HONEST, correctly labelled, but structurally unable to be registered
with any transparency service in the table above.

## What we took, and how each is proven

**1. RFC 8785 as the third canon profile** (`szl_evidence_core.jcs`, `CANON_JCS`).
Stdlib implementation, 174 lines. Differential test against the `rfc8785`
reference package: **20,012 / 20,012 doubles** (all 64-bit patterns sampled plus
the known layout edges) and **4,999 / 4,999 random documents** byte-identical,
including astral-character key ordering and C0-control escapes; the RFC's own
Appendix example reproduces exactly. Where Python and JCS disagree is now
measured, not guessed: `1e-07` vs `1e-7`, `1e+16` vs `10000000000000000`,
`1e-05` vs `0.00001`, code-point vs UTF-16 key order. Ints beyond 2**53 are
refused rather than rounded. The two Python profiles stay, because every
existing digest depends on them; new receipts should declare `rfc8785`.

**2. RFC 9162 Merkle commitments on the chain** (`szl_evidence_core.merkle`,
`UnifiedReceiptChain.checkpoint_v2`, `inclusion_proof`,
`verify_inclusion_proof`). Verified against the transparency-dev vectors the
Sigstore and CT implementations use: **9/9 roots** (tree sizes 0–8), **36/36
inclusion proofs**, **36/36 consistency proofs**, with wrong-leaf, wrong-index,
tampered-proof and rewritten-history negatives all rejected. A mutation that
removes the 0x00/0x01 domain separation fails four fixtures. The v1 checkpoint
and every hashed record byte are unchanged — `compat` still passes 53/53 against
the original kernels — so this is purely additive. A receipt consumer can now
hold one 32-byte root and an O(log n) proof instead of the ledger.

**3. The verification.\* distinction we already had, now named.** Krausz's
reason codes "separate a state's substance from a verifier's own instrument
failure". That is exactly the line this package's lattice draws between
`BLOCKED` (the subject failed) and `NOT_RUN` / `UNKNOWN` (the instrument could
not run), and the line SZL doctrine draws between MEASURED, MODELED and
UNAVAILABLE. We did not invent it and neither did he; it is now cross-referenced
so the vocabulary converges rather than drifts.

## What we did not take, and why

- **Signing.** DSSE, COSE and JWS are all one import away and all require key
  custody, rotation and a verification policy. Adding an envelope without those
  would upgrade the label from UNSIGNED_HONEST to signed while changing nothing
  about who can be trusted. The Merkle root is the right object to sign when
  that decision is made; the envelope is a day of work after the policy exists.
- **A transparency service.** Rekor v2 and Tessera are operational systems. A
  `checkpoint_v2` root is the exact object they register. Running or joining one
  is an infrastructure decision, not a library change.
- **COSE receipts.** The SCITT CCF profile is weeks from AD go-ahead. We align
  the data model (root, tree size, hash, inclusion path) so the mapping is
  mechanical when it lands, and we do not pre-implement a draft.

## Where this leaves the frontier

The leaders converged on one shape: canonical bytes → leaf hash → Merkle root →
signed checkpoint → registered receipt. SZL now has the first three as
standard-library code verified against the leaders' own vectors, the fourth as a
named decision, and the fifth as a mechanical mapping once the standard ships.
The part that is ours — typed evidence labels, a non-compensatory gate with a
contract and 60 golden vectors, a lattice that refuses to confuse "failed" with
"could not run", and a self-proving kernel pack that audits its own estate — sits
on top of that shape instead of beside it. That is what "make it our own" meant:
not a different construction, the same construction with our honesty rules
enforced at every layer.
