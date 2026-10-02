# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""szl_evidence_core: the primitives under every SZL receipt, extracted once.

Three layers, each a faithful extraction of what the estate already agrees on
and an explicit declaration of what it does not:

``canonical``   canonical JSON under two named profiles, algorithm-declared
                digests, fail-closed on NaN and non-string keys.
``chain``       ``UnifiedReceiptChain`` and ``ReceiptChain``, byte-compatible
                ports of the eleven ``_chain.py`` copies.
``lambda_gate`` the szl.lambda/v1 reference, vendored unchanged, plus a
                conformance checker for the seven gates that should call it.

Standard library only. No network, no signing, no claims beyond integrity.
"""

from .canonical import (  # noqa: F401
    ALGORITHMS,
    CANON_JCS,
    CANON_LAMBDA_V1,
    CANON_RECEIPT,
    DEFAULT_ALGORITHM,
    GENESIS,
    PROFILES,
    UNSIGNED_HONEST,
    CanonicalizationError,
    assert_json_safe,
    canonical_bytes,
    canonical_json,
    digest,
    digest_object,
    parse_prefixed_digest,
    prefixed_digest,
)
from .chain import (  # noqa: F401
    CHECKPOINT_SCHEMA,
    CHECKPOINT_V2_SCHEMA,
    ENVELOPE_SCHEMA,
    KERNEL_ALGORITHM,
    ChainVerification,
    ReceiptChain,
    UnifiedReceiptChain,
    tensor_digest,
)
from .jcs import JCSError, es_number, jcs_bytes, jcs_dumps  # noqa: F401
from .merkle import (  # noqa: F401
    MerkleError,
    consistency_proof,
    inclusion_proof,
    mth,
    verify_consistency,
    verify_inclusion,
)
from .lambda_gate import (  # noqa: F401
    CONJECTURE_1,
    ConformanceReport,
    LambdaV1Error,
    LambdaVerdict,
    check_conformance,
    evaluate,
    evaluate_mapping,
    gate_v1,
    lambda_v1,
    load_vectors,
    log_lambda_v1,
)

__version__ = "0.2.0"
__all__ = [name for name in dir() if not name.startswith("_")]
