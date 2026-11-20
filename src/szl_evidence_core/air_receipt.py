# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""SZL JSON profile of IETF AIR attested-inference receipts.

This module implements a JSON profile of IETF
``draft-tsyrulnikov-rats-attested-inference-receipt-02`` (AIR), whose CBOR
profile uses COSE_Sign1 with a CWT/EAT claims set. The corresponding AIR
private claims are -65537 ``model_id``, -65538 ``model_version``, -65539
``model_hash``, -65540 ``request_hash``, -65541 ``response_hash``, and
-65542 ``attestation_doc_hash``; ``cti``, ``eat_nonce``, and the CWT
``iat``/``nbf``/``exp`` time claims are carried by name as well.

This is a JSON profile carrying the same claim NAMES, not CBOR and not a
COSE_Sign1 implementation. Canonicalization is ``szl.canon/v1`` through the
repository canonicalization helpers, and the digest algorithm travels with
the digest as an algorithm-prefixed value. AIR-local checks (receipt shape,
canonical digest, time window, nonce, pins, optional signature verification)
are deliberately separate from platform verification of the referenced
attestation document and its hardware/root-of-trust appraisal.

Honesty boundary: an AIR receipt is Attester-signed Evidence, not an
appraisal verdict. Verification NEVER returns trust or GO; a successful
result accepts details only. Signatures are opaque because the Python
standard library has no Ed25519 implementation. Verification is therefore a
pluggable caller-supplied callable, and an absent verifier produces HOLD,
never a silent pass.

What this is not.

This is not a RATS Verifier, an endorsement or appraisal policy, a platform
TEE attestation verifier, a CBOR/COSE/CWT codec, a signature primitive, or a
statement that a model, request, response, or execution environment is
trusted. It does not fetch evidence, validate certificate chains, establish
an attester's identity, or turn an ACCEPT_DETAILS_ONLY result into GO.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Callable, Final

from .canonical import (
    CANON_RECEIPT,
    DEFAULT_ALGORITHM,
    GENESIS,
    UNSIGNED_HONEST,
    CanonicalizationError,
    assert_json_safe,
    canonical_bytes,
    canonical_json,
    parse_prefixed_digest,
    prefixed_digest,
)

SCHEMA: Final[str] = "szl.air-receipt/v1"
AIR_PROFILE: Final[str] = "https://spec.cyntrisec.com/air/v1"

VER_ACCEPT: Final[str] = "ACCEPT_DETAILS_ONLY"
VER_HOLD: Final[str] = "HOLD"

HOLD_MALFORMED_JSON: Final[str] = "HOLD_MALFORMED_JSON"
HOLD_SCHEMA_UNKNOWN: Final[str] = "HOLD_SCHEMA_UNKNOWN"
HOLD_UNSUPPORTED_PROFILE: Final[str] = "HOLD_UNSUPPORTED_PROFILE"
HOLD_REQUIRED_FIELD_MISSING: Final[str] = "HOLD_REQUIRED_FIELD_MISSING"
HOLD_NON_JSON_VALUE: Final[str] = "HOLD_NON_JSON_VALUE"
HOLD_CANON_MISMATCH: Final[str] = "HOLD_CANON_MISMATCH"
HOLD_EVIDENCE_HASH_MISMATCH: Final[str] = "HOLD_EVIDENCE_HASH_MISMATCH"
HOLD_CHAIN_BREAK: Final[str] = "HOLD_CHAIN_BREAK"
HOLD_CLOCK_UNSET: Final[str] = "HOLD_CLOCK_UNSET"
HOLD_EXPIRED: Final[str] = "HOLD_EXPIRED"
HOLD_NOT_YET_VALID: Final[str] = "HOLD_NOT_YET_VALID"
HOLD_NONCE_ENTROPY: Final[str] = "HOLD_NONCE_ENTROPY"
HOLD_PIN_MISMATCH: Final[str] = "HOLD_PIN_MISMATCH"
HOLD_SIGNATURE_REQUIRED: Final[str] = "HOLD_SIGNATURE_REQUIRED"
HOLD_SIGNATURE_VERIFIER_ABSENT: Final[str] = "HOLD_SIGNATURE_VERIFIER_ABSENT"
HOLD_SIGNATURE_INVALID: Final[str] = "HOLD_SIGNATURE_INVALID"

REQUIRED_CLAIMS: Final[tuple[str, ...]] = (
    "model_id",
    "model_version",
    "model_hash",
    "request_hash",
    "response_hash",
    "attestation_doc_hash",
    "attester_key_id",
    "cti",
    "eat_nonce",
    "iat",
)

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class AIRVerifyResult:
    """Local verification outcome; never a trust or platform appraisal result."""

    verdict: str
    reason: str
    details: dict

    def ok(self) -> bool:
        """Return whether receipt details passed all requested local checks."""

        return self.verdict == VER_ACCEPT


def _hold(reason: str, envelope: object = None) -> AIRVerifyResult:
    """Construct a non-throwing HOLD with only safely JSON-shaped details."""

    safe: dict = {}
    if isinstance(envelope, dict):
        try:
            assert_json_safe(envelope)
        except (CanonicalizationError, TypeError, ValueError):
            safe = {}
        else:
            safe = envelope
    return AIRVerifyResult(VER_HOLD, reason, {"envelope": safe})


def _signing_body(envelope: dict) -> dict:
    """Return the exact envelope projection covered by an opaque signature."""

    return {key: value for key, value in envelope.items() if key != "signature"}


def build_air_receipt(
    *,
    model_id: str,
    model_version: str,
    model_hash: str,
    request_hash: str,
    response_hash: str,
    attestation_doc_hash: str,
    attester_key_id: str,
    eat_nonce: str,
    iat: int,
    exp: int,
    nbf: int | None = None,
    cti: str | None = None,
    chain_prev_sha256: str = GENESIS,
    canon_profile: str = CANON_RECEIPT,
    algorithm: str = DEFAULT_ALGORITHM,
) -> dict:
    """Build an unsigned, honestly labelled AIR JSON evidence envelope."""

    strings = {
        "model_id": model_id,
        "model_version": model_version,
        "model_hash": model_hash,
        "request_hash": request_hash,
        "response_hash": response_hash,
        "attestation_doc_hash": attestation_doc_hash,
        "attester_key_id": attester_key_id,
        "eat_nonce": eat_nonce,
    }
    if cti is not None:
        strings["cti"] = cti
    for name, value in strings.items():
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} must be a non-empty string")
    if not isinstance(chain_prev_sha256, str) or not chain_prev_sha256:
        raise ValueError("chain_prev_sha256 must be a non-empty string")
    if not isinstance(canon_profile, str) or not canon_profile:
        raise ValueError("canon_profile must be a non-empty string")
    if not isinstance(algorithm, str) or not algorithm:
        raise ValueError("algorithm must be a non-empty string")
    if exp <= iat:
        raise ValueError("exp must be greater than iat")

    claims = {
        "air_profile": AIR_PROFILE,
        "model_id": model_id,
        "model_version": model_version,
        "model_hash": model_hash,
        "request_hash": request_hash,
        "response_hash": response_hash,
        "attestation_doc_hash": attestation_doc_hash,
        "attester_key_id": attester_key_id,
        "cti": str(uuid.uuid4()) if cti is None else cti,
        "eat_nonce": eat_nonce,
        "iat": iat,
        "exp": exp,
    }
    if nbf is not None:
        claims["nbf"] = nbf
    assert_json_safe(claims)

    return {
        "schema": SCHEMA,
        "air_profile": AIR_PROFILE,
        "canonicalization": canon_profile,
        "algorithm": algorithm,
        "claims": claims,
        "evidence_sha256": prefixed_digest(
            claims, algorithm, profile=canon_profile
        ),
        "chain_prev_sha256": chain_prev_sha256,
        "tier": UNSIGNED_HONEST,
        "signature": None,
    }


def sign_air_receipt(
    envelope: dict,
    *,
    signer: Callable[[bytes], str],
    key_id: str,
) -> dict:
    """Attach an opaque signer result without implementing cryptography here."""

    envelope2 = dict(envelope)
    body = {key: value for key, value in envelope2.items() if key != "signature"}
    sig = signer(canonical_bytes(body, profile=envelope2["canonicalization"]))
    envelope2["signature"] = {
        "alg": "Ed25519-opaque",
        "key_id": key_id,
        "value": sig,
    }
    envelope2["tier"] = "ED25519_OPAQUE"
    return envelope2


def verify_air_receipt(
    envelope: object,
    *,
    now: int | None = None,
    require_signature: bool = False,
    signature_verifier: Callable[[bytes, dict], bool] | None = None,
    expected_pins: dict | None = None,
    chain_head_sha256: str | None = None,
) -> AIRVerifyResult:
    """Fail closed on AIR-local checks; never appraise trust or return GO."""

    safe_envelope = envelope if isinstance(envelope, dict) else {}
    try:
        if not isinstance(envelope, dict):
            return _hold(HOLD_MALFORMED_JSON)
        if envelope.get("schema") != SCHEMA:
            return _hold(HOLD_SCHEMA_UNKNOWN, safe_envelope)
        if envelope.get("air_profile") not in (AIR_PROFILE,):
            return _hold(HOLD_UNSUPPORTED_PROFILE, safe_envelope)

        claims = envelope.get("claims")
        if not isinstance(claims, dict) or any(
            name not in claims for name in REQUIRED_CLAIMS
        ) or "exp" not in claims:
            return _hold(HOLD_REQUIRED_FIELD_MISSING, safe_envelope)

        try:
            assert_json_safe(envelope)
        except (CanonicalizationError, TypeError, ValueError):
            return _hold(HOLD_NON_JSON_VALUE, safe_envelope)

        algorithm = envelope.get("algorithm")
        canon_profile = envelope.get("canonicalization")
        stored_digest = envelope.get("evidence_sha256")
        if not isinstance(algorithm, str) or not isinstance(canon_profile, str):
            return _hold(HOLD_CANON_MISMATCH, safe_envelope)
        try:
            parsed_algorithm, _, declared = parse_prefixed_digest(stored_digest)
        except (CanonicalizationError, TypeError, ValueError):
            return _hold(HOLD_EVIDENCE_HASH_MISMATCH, safe_envelope)
        # The profile always carries prefixed digests; bare hex is an assumption
        # (declared=False) and fails closed here.
        if parsed_algorithm != algorithm or declared is not True:
            return _hold(HOLD_EVIDENCE_HASH_MISMATCH, safe_envelope)
        try:
            recomputed = prefixed_digest(
                claims, algorithm, profile=canon_profile
            )
        except (CanonicalizationError, TypeError, ValueError):
            return _hold(HOLD_CANON_MISMATCH, safe_envelope)
        if recomputed != stored_digest:
            return _hold(HOLD_EVIDENCE_HASH_MISMATCH, safe_envelope)

        chain_prev = envelope.get("chain_prev_sha256")
        if chain_prev != GENESIS and not (
            isinstance(chain_prev, str) and _HEX64.fullmatch(chain_prev)
        ):
            return _hold(HOLD_CHAIN_BREAK, safe_envelope)

        body = _signing_body(envelope)
        if chain_head_sha256 is not None:
            try:
                chain_link = prefixed_digest(
                    body, algorithm, profile=canon_profile
                )
            except (CanonicalizationError, TypeError, ValueError):
                return _hold(HOLD_CANON_MISMATCH, safe_envelope)
            if chain_link != chain_head_sha256:
                return _hold(HOLD_CHAIN_BREAK, safe_envelope)

        if now is None:
            return _hold(HOLD_CLOCK_UNSET, safe_envelope)
        if claims["exp"] <= now:
            return _hold(HOLD_EXPIRED, safe_envelope)
        nbf = claims.get("nbf")
        if nbf is not None and nbf > now:
            return _hold(HOLD_NOT_YET_VALID, safe_envelope)

        nonce = claims.get("eat_nonce")
        if not isinstance(nonce, str) or len(nonce) < 16:
            return _hold(HOLD_NONCE_ENTROPY, safe_envelope)

        signature = envelope.get("signature")
        if require_signature:
            if not isinstance(signature, dict):
                return _hold(HOLD_SIGNATURE_REQUIRED, safe_envelope)
            if signature_verifier is None:
                return _hold(HOLD_SIGNATURE_VERIFIER_ABSENT, safe_envelope)
            try:
                signing_bytes = canonical_bytes(body, profile=canon_profile)
                signature_valid = signature_verifier(signing_bytes, signature)
            except Exception:
                return _hold(HOLD_SIGNATURE_INVALID, safe_envelope)
            if signature_valid is not True:
                return _hold(HOLD_SIGNATURE_INVALID, safe_envelope)

        if expected_pins is not None:
            for key, expected in expected_pins.items():
                if key not in claims or claims[key] != expected:
                    return _hold(HOLD_PIN_MISMATCH, safe_envelope)

        return AIRVerifyResult(
            VER_ACCEPT,
            "OK_DETAILS_ONLY",
            {
                "envelope": envelope,
                "algorithm": algorithm,
                "evidence_sha256": stored_digest,
            },
        )
    except Exception:
        return AIRVerifyResult(
            VER_HOLD, HOLD_MALFORMED_JSON, {"envelope": {}}
        )


__all__ = [
    "AIR_PROFILE",
    "AIRVerifyResult",
    "HOLD_CANON_MISMATCH",
    "HOLD_CHAIN_BREAK",
    "HOLD_CLOCK_UNSET",
    "HOLD_EVIDENCE_HASH_MISMATCH",
    "HOLD_EXPIRED",
    "HOLD_MALFORMED_JSON",
    "HOLD_NONCE_ENTROPY",
    "HOLD_NON_JSON_VALUE",
    "HOLD_NOT_YET_VALID",
    "HOLD_PIN_MISMATCH",
    "HOLD_REQUIRED_FIELD_MISSING",
    "HOLD_SCHEMA_UNKNOWN",
    "HOLD_SIGNATURE_INVALID",
    "HOLD_SIGNATURE_REQUIRED",
    "HOLD_SIGNATURE_VERIFIER_ABSENT",
    "HOLD_UNSUPPORTED_PROFILE",
    "REQUIRED_CLAIMS",
    "SCHEMA",
    "VER_ACCEPT",
    "VER_HOLD",
    "build_air_receipt",
    "sign_air_receipt",
    "verify_air_receipt",
]
