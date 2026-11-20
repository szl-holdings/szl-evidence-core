# SPDX-License-Identifier: Apache-2.0
"""Conformance tests for the SZL AIR receipt admission profile."""

import copy

import pytest

from szl_evidence_core import air_receipt as M
from szl_evidence_core.canonical import CANON_RECEIPT, GENESIS, prefixed_digest


def FACTORY():
    """Build one honest, unsigned AIR receipt envelope."""

    return M.build_air_receipt(
        model_id="model-alpha",
        model_version="v1.2.3",
        model_hash="sha256:" + "aa" * 32,
        request_hash="sha256:" + "aa" * 32,
        response_hash="sha256:" + "aa" * 32,
        attestation_doc_hash="sha256:" + "aa" * 32,
        attester_key_id="attester-key-1",
        eat_nonce="0123456789abcdefghijklmn",
        iat=1700000000,
        exp=1700003600,
    )


def recompute(claims):
    """Recompute the honest prefixed evidence digest for mutated claims."""

    return prefixed_digest(claims, "sha256", profile=CANON_RECEIPT)


def body_digest(envelope):
    """Return the chain link digest of the envelope excluding ``signature``."""

    body = {key: value for key, value in envelope.items() if key != "signature"}
    return prefixed_digest(body, "sha256", profile=CANON_RECEIPT)


def test_happy_path_accepts_details_only():
    envelope = copy.deepcopy(FACTORY())

    result = M.verify_air_receipt(envelope, now=1700000100)

    assert result.verdict == M.VER_ACCEPT
    assert result.reason == "OK_DETAILS_ONLY"
    assert result.ok() is True


def test_wrong_schema_is_held():
    envelope = copy.deepcopy(FACTORY())
    envelope["schema"] = "szl.air-receipt/v2"

    result = M.verify_air_receipt(envelope, now=1700000100)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_SCHEMA_UNKNOWN


def test_wrong_air_profile_is_held():
    envelope = copy.deepcopy(FACTORY())
    envelope["air_profile"] = "https://example.invalid/air/v2"

    result = M.verify_air_receipt(envelope, now=1700000100)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_UNSUPPORTED_PROFILE


def test_missing_required_claim_is_held():
    envelope = copy.deepcopy(FACTORY())
    del envelope["claims"]["model_hash"]
    envelope["evidence_sha256"] = recompute(envelope["claims"])

    result = M.verify_air_receipt(envelope, now=1700000100)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_REQUIRED_FIELD_MISSING


def test_non_json_value_in_envelope_is_held():
    envelope = copy.deepcopy(FACTORY())
    envelope["not_json"] = {"a", "set"}

    result = M.verify_air_receipt(envelope, now=1700000100)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_NON_JSON_VALUE


def test_tampered_claims_with_stale_evidence_hash_are_held():
    envelope = copy.deepcopy(FACTORY())
    original_digest = envelope["evidence_sha256"]
    envelope["claims"]["model_id"] = "model-beta"

    assert envelope["evidence_sha256"] == original_digest
    result = M.verify_air_receipt(envelope, now=1700000100)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_EVIDENCE_HASH_MISMATCH


def test_bare_hex_evidence_digest_is_held():
    envelope = copy.deepcopy(FACTORY())
    envelope["evidence_sha256"] = recompute(envelope["claims"]).split(":", 1)[1]

    result = M.verify_air_receipt(envelope, now=1700000100)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_EVIDENCE_HASH_MISMATCH


def test_algorithm_disagreeing_with_digest_prefix_is_held():
    envelope = copy.deepcopy(FACTORY())
    assert envelope["evidence_sha256"].startswith("sha256:")
    envelope["algorithm"] = "sha512"

    result = M.verify_air_receipt(envelope, now=1700000100)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_EVIDENCE_HASH_MISMATCH


def test_malformed_chain_previous_hash_is_held():
    envelope = copy.deepcopy(FACTORY())
    envelope["chain_prev_sha256"] = "not-a-sha256-chain-value"

    result = M.verify_air_receipt(envelope, now=1700000100)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_CHAIN_BREAK


def test_clock_unset_is_held():
    envelope = copy.deepcopy(FACTORY())

    result = M.verify_air_receipt(envelope, now=None)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_CLOCK_UNSET


def test_now_after_expiry_is_held():
    envelope = copy.deepcopy(FACTORY())

    result = M.verify_air_receipt(envelope, now=1700003601)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_EXPIRED


def test_recomputed_future_nbf_is_held():
    envelope = copy.deepcopy(FACTORY())
    envelope["claims"]["nbf"] = 1700000200
    envelope["evidence_sha256"] = recompute(envelope["claims"])

    result = M.verify_air_receipt(envelope, now=1700000100)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_NOT_YET_VALID


def test_short_eat_nonce_is_held():
    envelope = copy.deepcopy(FACTORY())
    envelope["claims"]["eat_nonce"] = "short-nonce"
    envelope["evidence_sha256"] = recompute(envelope["claims"])

    result = M.verify_air_receipt(envelope, now=1700000100)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_NONCE_ENTROPY


def test_required_signature_without_signature_is_held():
    envelope = copy.deepcopy(FACTORY())
    assert envelope["signature"] is None

    result = M.verify_air_receipt(
        envelope,
        now=1700000100,
        require_signature=True,
        signature_verifier=lambda signing_bytes, signature: True,
    )

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_SIGNATURE_REQUIRED


def test_signed_envelope_without_verifier_is_held():
    envelope = copy.deepcopy(FACTORY())
    signed = M.sign_air_receipt(
        envelope,
        signer=lambda signing_bytes: "deadbeef",
        key_id="ak1",
    )

    result = M.verify_air_receipt(
        signed,
        now=1700000100,
        require_signature=True,
        signature_verifier=None,
    )

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_SIGNATURE_VERIFIER_ABSENT


def test_verifier_returning_false_is_held():
    envelope = copy.deepcopy(FACTORY())
    signed = M.sign_air_receipt(
        envelope,
        signer=lambda signing_bytes: "deadbeef",
        key_id="ak1",
    )

    result = M.verify_air_receipt(
        signed,
        now=1700000100,
        require_signature=True,
        signature_verifier=lambda signing_bytes, signature: False,
    )

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_SIGNATURE_INVALID


def test_verifier_that_raises_is_held():
    envelope = copy.deepcopy(FACTORY())
    signed = M.sign_air_receipt(
        envelope,
        signer=lambda signing_bytes: "deadbeef",
        key_id="ak1",
    )

    def raising_verifier(signing_bytes, signature):
        raise RuntimeError("deliberate verifier failure")

    result = M.verify_air_receipt(
        signed,
        now=1700000100,
        require_signature=True,
        signature_verifier=raising_verifier,
    )

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_SIGNATURE_INVALID


def test_valid_fake_signature_round_trip_accepts():
    envelope = copy.deepcopy(FACTORY())
    signed = M.sign_air_receipt(
        envelope,
        signer=lambda signing_bytes: "deadbeef",
        key_id="ak1",
    )

    def checker(signing_bytes, signature):
        assert isinstance(signing_bytes, bytes)
        return (
            signature["value"] == "deadbeef"
            and signature["key_id"] == "ak1"
        )

    result = M.verify_air_receipt(
        signed,
        now=1700000100,
        require_signature=True,
        signature_verifier=checker,
    )

    assert result.verdict == M.VER_ACCEPT
    assert result.reason == "OK_DETAILS_ONLY"


def test_expected_pins_mismatch_is_held():
    envelope = copy.deepcopy(FACTORY())

    result = M.verify_air_receipt(
        envelope,
        now=1700000100,
        expected_pins={"model_id": "a-different-model"},
    )

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_PIN_MISMATCH


def test_expected_pins_match_accepts():
    envelope = copy.deepcopy(FACTORY())
    expected_pins = {
        "model_id": envelope["claims"]["model_id"],
        "model_hash": envelope["claims"]["model_hash"],
        "attester_key_id": envelope["claims"]["attester_key_id"],
    }

    result = M.verify_air_receipt(
        envelope,
        now=1700000100,
        expected_pins=expected_pins,
    )

    assert result.verdict == M.VER_ACCEPT
    assert result.reason == "OK_DETAILS_ONLY"


def test_wrong_chain_head_hash_is_held():
    envelope = copy.deepcopy(FACTORY())
    wrong_head = "sha256:" + "bb" * 32
    assert wrong_head != body_digest(envelope)

    result = M.verify_air_receipt(
        envelope,
        now=1700000100,
        chain_head_sha256=wrong_head,
    )

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_CHAIN_BREAK


def test_correct_chain_head_hash_accepts():
    envelope = copy.deepcopy(FACTORY())
    expected_head = body_digest(envelope)

    result = M.verify_air_receipt(
        envelope,
        now=1700000100,
        chain_head_sha256=expected_head,
    )

    assert result.verdict == M.VER_ACCEPT
    assert result.reason == "OK_DETAILS_ONLY"


def test_none_envelope_is_held_as_malformed():
    result = M.verify_air_receipt(None, now=1700000100)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_MALFORMED_JSON


def test_list_envelope_is_held_as_malformed():
    result = M.verify_air_receipt([], now=1700000100)

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_MALFORMED_JSON


@pytest.mark.parametrize("envelope", [None, [], copy.deepcopy(FACTORY())])
def test_verdict_is_never_go_or_truthy_trust(envelope):
    result = M.verify_air_receipt(envelope, now=1700000100)

    assert result.verdict != "GO"
    assert result.verdict in {M.VER_ACCEPT, M.VER_HOLD}
    assert result.verdict not in {"TRUST", "TRUSTED", "TRUE", "PASS"}
    assert result.ok() is (result.verdict == M.VER_ACCEPT)
    if result.verdict == M.VER_ACCEPT:
        assert result.reason == "OK_DETAILS_ONLY"


@pytest.mark.parametrize("envelope", [None, []])
def test_malformed_container_inputs_never_raise(envelope):
    try:
        result = M.verify_air_receipt(envelope, now=1700000100)
    except Exception as exc:  # pragma: no cover - failure documentation
        pytest.fail(f"verification raised for {envelope!r}: {exc!r}")

    assert result.verdict == M.VER_HOLD
    assert result.reason == M.HOLD_MALFORMED_JSON


@pytest.mark.parametrize(
    "result",
    [
        M.verify_air_receipt(copy.deepcopy(FACTORY()), now=1700000100),
        M.verify_air_receipt(None, now=1700000100),
        M.verify_air_receipt([], now=1700000100),
    ],
)
def test_result_objects_expose_no_trust_or_go_attribute(result):
    attributes = set(dir(result))

    assert "trust" not in attributes
    assert "go" not in attributes
    assert not any(
        "trust" in name.lower() or "go" in name.lower().split("_")
        for name in attributes
    )
    assert not hasattr(result, "trust")
    assert not hasattr(result, "go")
    assert result.verdict != "GO"


@pytest.mark.parametrize(
    "overrides",
    [
        {"model_id": ""},
        {"model_version": ""},
        {"model_hash": ""},
        {"exp": 1700000000},
        {"exp": 1699999999},
        {"chain_prev_sha256": ""},
        {"canon_profile": ""},
        {"algorithm": ""},
    ],
)
def test_build_air_receipt_input_validation(overrides):
    arguments = {
        "model_id": "model-alpha",
        "model_version": "v1.2.3",
        "model_hash": "sha256:" + "aa" * 32,
        "request_hash": "sha256:" + "aa" * 32,
        "response_hash": "sha256:" + "aa" * 32,
        "attestation_doc_hash": "sha256:" + "aa" * 32,
        "attester_key_id": "attester-key-1",
        "eat_nonce": "0123456789abcdefghijklmn",
        "iat": 1700000000,
        "exp": 1700003600,
        "chain_prev_sha256": GENESIS,
        "canon_profile": CANON_RECEIPT,
        "algorithm": "sha256",
    }
    arguments.update(overrides)

    with pytest.raises(ValueError):
        M.build_air_receipt(**arguments)
