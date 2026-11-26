# Leader study: receipt-chain integrity primitives (szl-evidence-core)

Status: PROPOSE-only draft (leader-study/p15-20261126). Documentation only: does not merge
itself, change no module, no gate, no fixture, and admits nothing into training. The repo's
own posture governs everything said here: standard library only, no network, no signing,
no claim beyond integrity, UNSIGNED_HONEST.

## Why this study was written

szl-evidence-core holds the primitives under every SZL receipt, extracted once from the estate:
canonical JSON, algorithm-declared digests, SHA3-256 receipt chains byte-compatible with
szl-kernels, the szl.lambda/v1 reference with bitwise vectors, compatibility checks against
the original per-repo files, primitive-divergence audit across the estate, and gate exit codes
(0 PASS / 1 REVIEW / 2 BLOCKED / 3 NOT_RUN). The leaders below solved the same problems at
standards scale: canonical form, chained integrity, declared digest families, and test-vector
discipline. Each is a design pattern reference only; no equivalence, certification, or
validation status is claimed for this repo. All sources were opened and checked 2026-11-26.

## Leader 1: canonical form before hashing (RFC 8785, JSON Canonicalization Scheme)

A digest over JSON is only reproducible if the bytes were canonical first. RFC 8785 defines a
single strict canonical form: sorted keys, no insignificant whitespace, defined number and
string serialization (https://www.rfc-editor.org/rfc/rfc8785). Pattern for this repo's
canonical-JSON module and its compat byte-equality checks: implementations that diverge on
serialization will disagree even when the logical content matches, so naming the canonical
scheme beside every digest is what makes a chain auditable across 99 repositories
(https://www.rfc-editor.org/rfc/rfc8785#name-generation-of-canonical-json).

## Leader 2: append-only receipt chains (RFC 6962, Certificate Transparency)

Certificate Transparency standardized the append-only, hash-chained log: each entry bound to
the previous, Merkle roots published, inclusion proofs verifiable against a signed tree head
(https://www.rfc-editor.org/rfc/rfc6962). Pattern for the SHA3-256 receipt-chain module: a
chain where each receipt binds its predecessor gives the same property the estate already
relies on, tamper-evidence by construction. The analogy is structural only; this repo makes no
signing claim (it is UNSIGNED_HONEST by its own statement) and no log-operator or cryptographic
guarantee beyond integrity is inherited from CT.

## Leader 3: declared digest families (NIST SP 800-185, SHA-3 derived functions)

Algorithm-declared digests only mean something when the family itself is standardized. NIST
SP 800-185 specifies SHA-3 derived functions with defined input conventions
(https://csrc.nist.gov/publications/detail/sp/800-185/final; the base SHA-3 standard is FIPS
202, https://csrc.nist.gov/publications/detail/fips/202/final). Pattern for the repo's
SHA3-256 chains: declaring the algorithm per receipt is what lets an auditor reproduce the
digest years later; an undeclared digest is an unverifiable claim.

## Leader 4: known-answer vector discipline (NIST CAVP)

The Cryptographic Algorithm Validation Program validates implementations against published
known-answer test vectors, so "correct" means bitwise agreement with the reference, not
"looks right" (https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).
Pattern for the szl.lambda/v1 reference vectors: the repo's own 60/60 bitwise standard and its
compat/audit commands apply the same idea, checking estate implementations against golden
vectors and reporting divergence instead of trusting descriptions. This is the estate's
MEASURED-over-claimed doctrine expressed as a test suite.

## What is deliberately NOT adopted or claimed

- No network layer, no signing, no key management is added or implied; the repo's own
  "no claim beyond integrity" bound is preserved verbatim here.
- No CAVP validation, FIPS claim, or CT compliance is claimed for this repo or the estate.
- Nothing here changes fixtures, gates, module code, or admits any artifact into training.

## Provenance

Branch off main at pinned HEAD 56ff432b8f9074876b939845bb2751a8e73bac1b (reconfirmed at
execution). Governance: Kimi cloud rail GO, nonce P15-EVIDCORE-GOV-4a6b8f21d3 (nonce-echo
verified, 46.7s). Sources verified 2026-11-26. Merge requires explicit owner approval;
A1-A4 remain UNAPPROVED.
