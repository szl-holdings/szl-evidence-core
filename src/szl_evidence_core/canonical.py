# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Canonical serialization and digest primitives shared by every SZL receipt.

Why this module exists. The 2026-10-01 estate audit measured 35 receipt
implementations across 99 repositories (25 ``receipts.py``, 11 ``_chain.py``
and the ``receipt.py`` family) and found that they are *not* one drifted
module: ``receipts.py`` alone has 22 distinct API surfaces with a median
pairwise Jaccard of 0.000. What they do share is the layer underneath, and
that layer disagrees in ways that silently break cross-organ verification:

The numbers below count only ``json.dumps`` calls that demonstrably feed a
digest (32 of the 35 files have at least one; pretty-printed writes and
snapshot round-trips are excluded). ``python -m szl_evidence_core audit``
reproduces them.

  * **hash algorithm** - 22 files use SHA-256, 12 use SHA3-256, 1 uses both,
    and nothing in a receipt body records which. A chain written by a torch-ext
    kernel cannot be verified by a service verifier. Neither choice is wrong;
    the missing declaration is.
  * **allow_nan** - 21 of 32 hash-feeding files never pass ``allow_nan=False``;
    11 are strict. The Python default emits bare ``NaN``, which is not JSON.
    Such a receipt hashes fine locally and cannot be parsed by any conforming
    external reader.
  * **ensure_ascii** - 7 of 32 hash with ``ensure_ascii=False`` (a11oy/amaru,
    ayllu, szl-quant-bench, szl-retrieval-bench, vertical-services, szl-nemo);
    the other 25 rely on the default (True). The same non-ASCII string hashes
    to two different digests across those two groups today. The estate's formal
    Λ contract, ``szl.lambda/v1``, also pins ``ensure_ascii=False``. Both are
    legitimate, so this module names them as two profiles rather than
    pretending there is one.
  * **separators** - 1 hash-feeding file (``szl-gov/tools/receipt.py``) omits
    ``separators=(",", ":")``, so its digests differ from every other organ's
    on whitespace alone.
  * **genesis** - 20 of 35 use 64 zeros; the rest use bespoke sentinels.

Every parameter that can change the bytes is passed explicitly, the algorithm
travels with the digest, and non-JSON floats are refused at emit time rather
than discovered at verify time.

Nothing here is signed. A hash chain detects tampering by anyone who cannot
rewrite the whole chain; it does not authenticate the publisher. The honest
tier label for that posture is UNSIGNED_HONEST and it is carried in receipts.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any, Final

__all__ = [
    "CANON_RECEIPT",
    "CANON_LAMBDA_V1",
    "CANON_UTF8",
    "PROFILES",
    "ALGORITHMS",
    "DEFAULT_ALGORITHM",
    "GENESIS",
    "UNSIGNED_HONEST",
    "CanonicalizationError",
    "assert_json_safe",
    "canonical_json",
    "canonical_bytes",
    "digest",
    "digest_object",
    "prefixed_digest",
    "parse_prefixed_digest",
]

#: ASCII-escaped profile. Matches 25 of the 32 hash-feeding receipt files and
#: the hardened szl_kernels chain, so every ledger they have written verifies
#: under it. Default for receipts.
CANON_RECEIPT: Final[str] = "szl.canon/v1"

#: UTF-8 profile. Matches spec/szl.lambda.v1.json ``vectors.digest`` exactly
#: and the 7 receipt files that hash with ``ensure_ascii=False``. Named after
#: the one written contract that pins it.
CANON_LAMBDA_V1: Final[str] = "szl.lambda/v1"
CANON_UTF8: Final[str] = CANON_LAMBDA_V1

#: The two profiles the estate actually uses. Both sort keys, use compact
#: separators and refuse NaN/Infinity; they differ only in ASCII escaping.
PROFILES: Final[dict[str, dict[str, Any]]] = {
    CANON_RECEIPT: {"ensure_ascii": True},
    CANON_LAMBDA_V1: {"ensure_ascii": False},
}

#: Supported digest algorithms. The name is recorded alongside every digest so
#: a verifier never has to guess, which is the defect this package fixes.
ALGORITHMS: Final[dict[str, Any]] = {
    "sha256": hashlib.sha256,
    "sha3_256": hashlib.sha3_256,
    "sha512": hashlib.sha512,
}

#: SHA-256 is the estate-wide default: 22 of 35 files use it and external
#: tooling (in-toto, Sigstore, CycloneDX, SWHID) expects it. The kernel chains
#: in ``chain.py`` default to SHA3-256 because all eleven of their sources did
#: and their existing ledgers must keep verifying. Declaring the algorithm is
#: what makes both choices coexist.
DEFAULT_ALGORITHM: Final[str] = "sha256"

#: 20 of 35 files already use 64 zeros; the rest use bespoke sentinels, which
#: makes a chain's first link unverifiable by a generic reader.
GENESIS: Final[str] = "0" * 64

#: Trust tier. Hash-chained and replayable; not signed and not zero-knowledge.
UNSIGNED_HONEST: Final[str] = "UNSIGNED_HONEST"

_HEX = re.compile(r"^[0-9a-f]{64}$|^[0-9a-f]{128}$")
_PREFIXED = re.compile(r"^([a-z0-9_]+):([0-9a-f]{64}|[0-9a-f]{128})$")


class CanonicalizationError(ValueError):
    """A value cannot be canonicalised without ambiguity.

    Fail-closed: a value that cannot be serialised to valid, stable JSON must
    not be hashed at all. Hashing it anyway yields a digest that looks
    authoritative and verifies nowhere.
    """


def assert_json_safe(value: Any, _path: str = "$") -> None:
    """Reject anything that cannot round-trip through conforming JSON.

    The default ``json.dumps`` writes ``NaN``, ``Infinity`` and ``-Infinity``,
    none of which are JSON. It also accepts non-string mapping keys and
    silently coerces them, so ``{1: "a"}`` and ``{"1": "a"}`` collide. Both are
    refused here, with the path to the offender.
    """
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError(
                f"{_path}: {value!r} is not representable in JSON; a receipt "
                "containing it cannot be verified by a conforming reader")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"{_path}: mapping key {key!r} is {type(key).__name__}, not str; "
                    "non-string keys are coerced and collide with their string form")
            assert_json_safe(item, f"{_path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            assert_json_safe(item, f"{_path}[{index}]")
        return
    raise CanonicalizationError(
        f"{_path}: {type(value).__name__} is not JSON-serialisable; convert it "
        "explicitly rather than relying on a default= hook, which is not stable")


def _profile(profile: str) -> dict[str, Any]:
    try:
        return PROFILES[profile]
    except KeyError:
        raise CanonicalizationError(
            f"unknown canon profile {profile!r}; known: {sorted(PROFILES)}") from None


def canonical_json(value: Any, *, profile: str = CANON_RECEIPT,
                   check: bool = True) -> str:
    """Canonical JSON text under a named profile.

    Every argument that affects the output bytes is passed explicitly. Relying
    on defaults is how the estate ended up with three byte encodings of the
    same object. ``check=False`` skips the structural pre-check and relies on
    ``allow_nan=False`` alone, which is what the hardened kernel chain does and
    is required for byte-identical compatibility with it.
    """
    options = _profile(profile)
    if check:
        assert_json_safe(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=options["ensure_ascii"],
        allow_nan=False,
    )


def canonical_bytes(value: Any, *, profile: str = CANON_RECEIPT,
                    check: bool = True) -> bytes:
    """UTF-8 bytes of the canonical form. This is what gets hashed."""
    return canonical_json(value, profile=profile, check=check).encode("utf-8")


def digest(data: bytes, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Hex digest of raw bytes under a named algorithm."""
    try:
        constructor = ALGORITHMS[algorithm]
    except KeyError:
        raise CanonicalizationError(
            f"unknown algorithm {algorithm!r}; supported: {sorted(ALGORITHMS)}") from None
    return constructor(data).hexdigest()


def digest_object(value: Any, algorithm: str = DEFAULT_ALGORITHM, *,
                  profile: str = CANON_RECEIPT, check: bool = True) -> str:
    """Digest of a value's canonical form."""
    return digest(canonical_bytes(value, profile=profile, check=check), algorithm)


def prefixed_digest(value: Any, algorithm: str = DEFAULT_ALGORITHM, *,
                    profile: str = CANON_RECEIPT, check: bool = True) -> str:
    """``algorithm:hex`` so the digest is self-describing.

    An unprefixed hex string does not say how it was produced, so a SHA-256 and
    a SHA3-256 digest of the same body are indistinguishable strings that never
    match. Carrying the algorithm is what makes cross-organ verification
    possible at all.
    """
    return f"{algorithm}:{digest_object(value, algorithm, profile=profile, check=check)}"


def parse_prefixed_digest(text: str) -> tuple[str, str, bool]:
    """Split ``algorithm:hex`` into ``(algorithm, hex, declared)``.

    Bare hex is accepted for the chains already written without a prefix, but
    its algorithm is *assumed* to be the default and ``declared`` is False so a
    caller can tell knowledge from assumption.
    """
    if not isinstance(text, str):
        raise CanonicalizationError(f"not a digest: {text!r}")
    match = _PREFIXED.match(text)
    if match:
        algorithm, hexdigest = match.group(1), match.group(2)
        if algorithm not in ALGORITHMS:
            raise CanonicalizationError(f"unknown algorithm {algorithm!r} in {text!r}")
        return algorithm, hexdigest, True
    if _HEX.match(text):
        return DEFAULT_ALGORITHM, text, False
    raise CanonicalizationError(f"not a digest: {text!r}")
