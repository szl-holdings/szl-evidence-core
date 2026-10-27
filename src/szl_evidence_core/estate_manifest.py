# SPDX-License-Identifier: Apache-2.0
"""Fail-closed validation and admission for the SZL estate manifest.

Only already-captured evidence is interpreted here. This module never fetches,
signs, publishes, or authorizes an external effect.
"""
from __future__ import annotations
import hashlib, json, re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

SCHEMA_VERSION = "1.0.0"
STATUSES = frozenset({"PROVED","CONDITIONAL","AXIOM_GATED","OPERATIONAL","QUALIFIED","CONJECTURE","SORRY","UNVERIFIED","SOURCE_UNBOUND","HISTORICAL"})
KINDS = frozenset({"claim","artifact","runtime","domain","vertical"})
SIGNATURE_STATES = frozenset({"VERIFIED","UNVERIFIED","ABSENT","SKIPPED"})
DECISIONS = frozenset({"ALLOW","ADVISORY","ABSTAIN","DENY","INCOMPARABLE"})
SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

class ManifestError(ValueError):
    """The manifest is malformed."""

@dataclass(frozen=True)
class Admission:
    decision: str
    reasons: tuple[str, ...]
    def __post_init__(self) -> None:
        if self.decision not in DECISIONS:
            raise ValueError(f"unknown admission decision: {self.decision}")
    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"
    def as_dict(self) -> dict[str, Any]:
        return {"decision": self.decision, "reasons": list(self.reasons)}

def _need(condition: bool, message: str, errors: list[str]) -> None:
    if not condition: errors.append(message)

def _obj(value: Any, field: str, errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{field}: object required")
        return None
    return value

def _time(value: Any, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str) or not value:
        errors.append(f"{field}: UTC timestamp required"); return None
    try: parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{field}: invalid ISO-8601 timestamp"); return None
    if parsed.tzinfo is None:
        errors.append(f"{field}: timezone required"); return None
    return parsed.astimezone(timezone.utc)

def _digest(value: Any, pattern: re.Pattern[str], field: str, errors: list[str]) -> None:
    _need(isinstance(value, str) and bool(pattern.fullmatch(value)), f"{field}: exact digest required", errors)

def _github(value: Any, errors: list[str]) -> None:
    if value is None: return
    item = _obj(value, "github", errors)
    if item is None: return
    for key in ("repository","ref_type","revision","path","artifact_digest"):
        _need(key in item, f"github.{key}: required", errors)
    _need(isinstance(item.get("repository"), str) and "/" in str(item.get("repository")), "github.repository: owner/name required", errors)
    _need(item.get("ref_type") in {"commit","tag","branch"}, "github.ref_type: invalid", errors)
    if item.get("ref_type") == "branch": errors.append("github.ref_type: branch-only bindings are not admissible")
    _digest(item.get("revision"), SHA1, "github.revision", errors)
    _digest(item.get("artifact_digest"), SHA256, "github.artifact_digest", errors)
    _need(isinstance(item.get("path"), str) and bool(item.get("path")), "github.path: non-empty path required", errors)

def _hf(value: Any, errors: list[str]) -> None:
    if value is None: return
    item = _obj(value, "hf", errors)
    if item is None: return
    for key in ("organization","asset_type","name","revision","artifact_digest","license","served_bytes_sha256","readback_at"):
        _need(key in item, f"hf.{key}: required", errors)
    _need(isinstance(item.get("organization"), str) and bool(item.get("organization")), "hf.organization: required", errors)
    _need(item.get("asset_type") in {"model","dataset","space","kernel"}, "hf.asset_type: invalid", errors)
    _need(isinstance(item.get("name"), str) and bool(item.get("name")), "hf.name: required", errors)
    _digest(item.get("revision"), SHA1, "hf.revision", errors)
    _digest(item.get("artifact_digest"), SHA256, "hf.artifact_digest", errors)
    _digest(item.get("served_bytes_sha256"), SHA256, "hf.served_bytes_sha256", errors)
    _need(isinstance(item.get("license"), str) and bool(item.get("license")), "hf.license: required", errors)
    _time(item.get("readback_at"), "hf.readback_at", errors)
    if item.get("source_revision") is not None: _digest(item.get("source_revision"), SHA1, "hf.source_revision", errors)

def _domain(value: Any, errors: list[str]) -> None:
    if value is None: return
    item = _obj(value, "domain", errors)
    if item is None: return
    for key in ("url","observed_at","served_bytes_sha256","source_revision"):
        _need(key in item, f"domain.{key}: required", errors)
    _need(isinstance(item.get("url"), str) and str(item.get("url")).startswith("https://"), "domain.url: HTTPS required", errors)
    _time(item.get("observed_at"), "domain.observed_at", errors)
    _digest(item.get("served_bytes_sha256"), SHA256, "domain.served_bytes_sha256", errors)
    if item.get("source_revision") is not None: _digest(item.get("source_revision"), SHA1, "domain.source_revision", errors)

def _verification(value: Any, errors: list[str]) -> None:
    item = _obj(value, "verification", errors)
    if item is None: return
    for key in ("verifier_version","workflow_run_ids","security_results","signer_identity","signature_status","freshness","rollback_pointer"):
        _need(key in item, f"verification.{key}: required", errors)
    _need(isinstance(item.get("verifier_version"), str) and bool(item.get("verifier_version")), "verification.verifier_version: required", errors)
    _need(isinstance(item.get("workflow_run_ids"), list), "verification.workflow_run_ids: list required", errors)
    _need(isinstance(item.get("security_results"), list), "verification.security_results: list required", errors)
    _need(isinstance(item.get("signer_identity"), str) and bool(item.get("signer_identity")), "verification.signer_identity: required", errors)
    _need(item.get("signature_status") in SIGNATURE_STATES, "verification.signature_status: invalid", errors)
    _time(item.get("freshness"), "verification.freshness", errors)
    _need(isinstance(item.get("rollback_pointer"), str) and bool(item.get("rollback_pointer")), "verification.rollback_pointer: required", errors)

def _receipt(value: Any, errors: list[str]) -> None:
    item = _obj(value, "receipt", errors)
    if item is None: return
    for key in ("id","source_revision","artifact_digest","signer","signature_status","issued_at"):
        _need(key in item, f"receipt.{key}: required", errors)
    _need(isinstance(item.get("id"), str) and bool(item.get("id")), "receipt.id: required", errors)
    _digest(item.get("source_revision"), SHA1, "receipt.source_revision", errors)
    _digest(item.get("artifact_digest"), SHA256, "receipt.artifact_digest", errors)
    _need(isinstance(item.get("signer"), str) and bool(item.get("signer")), "receipt.signer: required", errors)
    _need(item.get("signature_status") in SIGNATURE_STATES, "receipt.signature_status: invalid", errors)
    _time(item.get("issued_at"), "receipt.issued_at", errors)

def _language(value: Any, errors: list[str]) -> None:
    item = _obj(value, "allowed_language", errors)
    if item is None: return
    expected = {"product","runtime","research","marketing"}
    _need(set(item) == expected, "allowed_language: exactly product/runtime/research/marketing keys required", errors)
    for key in expected: _need(isinstance(item.get(key), str) and bool(str(item.get(key)).strip()), f"allowed_language.{key}: non-empty text required", errors)

def validate_record(record: Any) -> list[str]:
    errors: list[str] = []
    item = _obj(record, "record", errors)
    if item is None: return errors
    for key in ("id","kind","name","owner","scope","status","github","hf","domain","verification","allowed_language","receipt"):
        _need(key in item, f"{key}: required", errors)
    _need(isinstance(item.get("id"), str) and bool(item.get("id")), "id: required", errors)
    _need(item.get("kind") in KINDS, "kind: invalid", errors)
    _need(isinstance(item.get("name"), str) and bool(item.get("name")), "name: required", errors)
    _need(isinstance(item.get("owner"), str) and bool(item.get("owner")), "owner: required", errors)
    _need(isinstance(item.get("scope"), str) and bool(item.get("scope")), "scope: required", errors)
    _need(item.get("status") in STATUSES, "status: invalid", errors)
    _github(item.get("github"), errors); _hf(item.get("hf"), errors); _domain(item.get("domain"), errors)
    _verification(item.get("verification"), errors); _language(item.get("allowed_language"), errors); _receipt(item.get("receipt"), errors)
    return errors

def validate_manifest(manifest: Any) -> list[str]:
    errors: list[str] = []
    item = _obj(manifest, "manifest", errors)
    if item is None: return errors
    for key in ("schema_version","manifest_id","revision","generated_at","records"):
        _need(key in item, f"{key}: required", errors)
    _need(item.get("schema_version") == SCHEMA_VERSION, "schema_version: unsupported", errors)
    _need(isinstance(item.get("manifest_id"), str) and bool(item.get("manifest_id")), "manifest_id: required", errors)
    _digest(item.get("revision"), SHA1, "revision", errors); _time(item.get("generated_at"), "generated_at", errors)
    records = item.get("records")
    _need(isinstance(records, list) and bool(records), "records: non-empty list required", errors)
    if not isinstance(records, list): return errors
    seen: set[str] = set()
    for index, record in enumerate(records):
        errors.extend(f"records[{index}].{message}" for message in validate_record(record))
        if isinstance(record, Mapping) and isinstance(record.get("id"), str):
            if record["id"] in seen: errors.append(f"records[{index}].id: duplicate {record['id']}")
            seen.add(record["id"])
    return errors

def _fresh(value: Any, now: datetime, max_age_seconds: int, field: str, reasons: list[str]) -> bool:
    parsed = _time(value, field, reasons)
    if parsed is None: return False
    age = (now - parsed).total_seconds()
    if age < 0 or age > max_age_seconds: reasons.append(f"{field}: stale or future evidence"); return False
    return True

def _bound(record: Mapping[str, Any], reasons: list[str]) -> bool:
    github = record.get("github")
    if not isinstance(github, Mapping) or not SHA1.fullmatch(str(github.get("revision",""))) or github.get("ref_type") == "branch":
        reasons.append("exact GitHub source revision unavailable"); return False
    hf = record.get("hf")
    if hf is not None:
        if not isinstance(hf, Mapping) or not SHA1.fullmatch(str(hf.get("revision",""))): reasons.append("exact Hugging Face revision unavailable"); return False
        if not SHA256.fullmatch(str(hf.get("served_bytes_sha256",""))): reasons.append("Hugging Face served-byte readback unavailable"); return False
        if hf.get("source_revision") != github.get("revision"): reasons.append("Hugging Face source revision is not bound to GitHub"); return False
    domain = record.get("domain")
    if domain is not None:
        if not isinstance(domain, Mapping) or not str(domain.get("url","")).startswith("https://"): reasons.append("HTTPS domain observation unavailable"); return False
        if not SHA256.fullmatch(str(domain.get("served_bytes_sha256",""))): reasons.append("domain served-byte readback unavailable"); return False
        if domain.get("source_revision") != github.get("revision"): reasons.append("domain source revision is not bound to GitHub"); return False
    return True

def admit(record: Mapping[str, Any], *, now: datetime | None = None, max_age_seconds: int = 86400) -> Admission:
    structural = validate_record(record)
    if structural: return Admission("DENY", tuple(structural))
    if max_age_seconds <= 0: return Admission("DENY", ("max_age_seconds must be positive",))
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    status = record["status"]
    if status in {"SOURCE_UNBOUND","HISTORICAL"}: return Admission("INCOMPARABLE", (f"status {status} is not admissible",))
    if status in {"CONJECTURE","SORRY","UNVERIFIED"}: return Admission("DENY", (f"status {status} fails closed",))
    reasons: list[str] = []
    if not _bound(record, reasons): return Admission("INCOMPARABLE", tuple(reasons))
    verification, receipt = record["verification"], record["receipt"]
    assert isinstance(verification, Mapping) and isinstance(receipt, Mapping)
    if verification["signature_status"] != "VERIFIED" or receipt["signature_status"] != "VERIFIED": return Admission("DENY", ("signed verification is required",))
    if verification["signer_identity"] != receipt["signer"]: return Admission("DENY", ("receipt signer does not match verification signer",))
    github = record["github"]; assert isinstance(github, Mapping)
    if receipt["source_revision"] != github["revision"] or receipt["artifact_digest"] != github["artifact_digest"]: return Admission("DENY", ("receipt is not hash-linked to the GitHub source record",))
    if not _fresh(verification["freshness"], now, max_age_seconds, "verification.freshness", reasons): return Admission("DENY", tuple(reasons))
    if not _fresh(receipt["issued_at"], now, max_age_seconds, "receipt.issued_at", reasons): return Admission("DENY", tuple(reasons))
    hf, domain = record.get("hf"), record.get("domain")
    if isinstance(hf, Mapping) and not _fresh(hf.get("readback_at"), now, max_age_seconds, "hf.readback_at", reasons): return Admission("INCOMPARABLE", tuple(reasons))
    if isinstance(domain, Mapping) and not _fresh(domain.get("observed_at"), now, max_age_seconds, "domain.observed_at", reasons): return Admission("INCOMPARABLE", tuple(reasons))
    if record["kind"] in {"runtime","vertical"} and not verification["rollback_pointer"]: return Admission("DENY", ("rollback pointer required for consequential records",))
    if status == "PROVED" and record["kind"] == "claim":
        proof = verification.get("proof")
        if not isinstance(proof, Mapping): return Admission("DENY", ("PROVED claim requires explicit proof witness",))
        for key in ("lake_build","theorem_symbol","axioms","sorry_count","cross_check","source_revision"):
            if key not in proof: return Admission("DENY", (f"proof.{key}: required",))
        if proof["lake_build"] != "PASS" or proof["sorry_count"] != 0: return Admission("DENY", ("proof witness is not clean",))
        if proof["source_revision"] != github["revision"]: return Admission("DENY", ("proof witness source revision mismatch",))
    if status in {"CONDITIONAL","AXIOM_GATED"}: return Admission("ADVISORY", (f"status {status} permits advisory use only",))
    return Admission("ALLOW", ("exact source, fresh signed receipt, and readback evidence present",))

def load_manifest(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8")); errors = validate_manifest(data)
    if errors: raise ManifestError("; ".join(errors))
    return data

def canonical_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",",":"), ensure_ascii=True, allow_nan=False).encode("utf-8")

def manifest_sha256(manifest: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()

