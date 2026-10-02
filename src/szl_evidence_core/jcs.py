# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""RFC 8785 JSON Canonicalization Scheme (JCS), standard library only.

Why a third profile. The estate's two existing profiles (``szl.canon/v1``
ASCII-escaped, ``szl.lambda/v1`` UTF-8) are both "whatever Python's json.dumps
does with sort_keys". That is stable *within* Python and unspecified anywhere
else: a Go, Rust or JavaScript verifier has no document to implement. RFC 8785
is the one canonical JSON with an RFC number and independent implementations
(rfc8785 in Python, the Go/JS/Java/.NET references). It is what SCITT COSE
receipts, Rekor v2 and the verification.* draft point at when they say
"canonical". Adopting it makes an SZL digest checkable by a verifier that has
never seen SZL code.

Where Python's json.dumps and JCS disagree, measured on this module's own
differential test against the ``rfc8785`` reference:

  * **Numbers.** JCS requires ECMAScript ``Number::toString`` (ES2019
    §7.1.12.1 incl. Note 2): shortest round-trip digits, plain notation for
    1e-6 <= |x| < 1e21, exponent form ``1e-7`` / ``1e+21`` otherwise. Python
    writes ``1e-07``, ``1e+16`` and ``1e-05`` where JCS writes ``1e-7``,
    ``10000000000000000`` and ``0.00001``. ``-0`` is serialised ``0``
    (RFC 8785 errata 7920).
  * **Integers.** JCS numbers are IEEE doubles. An int beyond ±2**53 cannot be
    represented exactly, so it is refused here rather than silently rounded.
  * **Key order.** JCS sorts property names by UTF-16 code units; Python sorts
    by code point. They differ once a name contains an astral character:
    U+10000 (``D800 DC00``) sorts *before* U+E000 in UTF-16 and after it by
    code point.
  * **Strings.** Identical to ``ensure_ascii=False`` escaping: ``\\b \\t \\n \\f
    \\r``, other C0 controls as ``\\u00XX`` lowercase, ``\\\\`` and ``\\"``,
    everything else as-is. Lone surrogates are an error.

Nothing here is signed. JCS fixes the bytes; it does not authenticate them.
"""

from __future__ import annotations

import math
from typing import Any

__all__ = ["CANON_JCS", "JCSError", "jcs_dumps", "jcs_bytes", "es_number"]

CANON_JCS = "rfc8785"
_MAX_SAFE = 2 ** 53


class JCSError(ValueError):
    """A value has no RFC 8785 representation."""


# --------------------------------------------------------------------------- #
# numbers: ECMAScript Number::toString                                        #
# --------------------------------------------------------------------------- #

def es_number(x: float) -> str:
    """Serialise a finite double exactly as ECMAScript ``Number::toString``.

    Python's ``repr`` already yields the shortest round-trip digit string; only
    the layout differs, so the digits and decimal exponent are taken from
    ``repr`` and re-laid-out per ES2019 §7.1.12.1 (k digits, exponent n).
    """
    if not math.isfinite(x):
        raise JCSError(f"{x!r} is not a JSON number")
    if x == 0:
        return "0"                       # covers -0.0 (errata 7920)
    sign = "-" if x < 0 else ""
    r = repr(abs(x))                     # shortest round-trip, e.g. '1.5e-07', '123.0', '1e+21'
    if "e" in r:
        mant, exp = r.split("e")
        exp10 = int(exp)
    else:
        mant, exp10 = r, 0
    if "." in mant:
        int_part, frac_part = mant.split(".")
    else:
        int_part, frac_part = mant, ""
    digits = (int_part + frac_part).lstrip("0")
    # position of the decimal point relative to the start of `digits`
    n = len(int_part.lstrip("0")) + exp10 if int_part.lstrip("0") else exp10 - (len(frac_part) - len(frac_part.lstrip("0")))
    if not int_part.lstrip("0"):
        # mantissa like 0.000123 -> digits '123', point is after -3 leading zeros
        lead = len(frac_part) - len(frac_part.lstrip("0"))
        n = -lead + exp10
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    # ES2019 7.1.12.1 steps 6-10
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    es = ("+" if e >= 0 else "-") + str(abs(e))
    if k == 1:
        return sign + digits + "e" + es
    return sign + digits[0] + "." + digits[1:] + "e" + es


# --------------------------------------------------------------------------- #
# strings                                                                     #
# --------------------------------------------------------------------------- #

_ESC = {"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r", '"': '\\"', "\\": "\\\\"}


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch in _ESC:
            out.append(_ESC[ch])
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        elif 0xD800 <= o <= 0xDFFF:
            raise JCSError(f"lone surrogate U+{o:04X} has no UTF-8 form")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(name: str) -> bytes:
    """Sort key: the name as UTF-16 code units, compared as unsigned integers."""
    try:
        return name.encode("utf-16-be")
    except UnicodeEncodeError as exc:
        raise JCSError(f"property name {name!r}: {exc.reason}") from None


# --------------------------------------------------------------------------- #
# serializer                                                                  #
# --------------------------------------------------------------------------- #

def _ser(value: Any, path: str) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE:
            raise JCSError(f"{path}: integer {value} exceeds 2**53; JCS numbers are IEEE doubles")
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise JCSError(f"{path}: {value!r} is not a JSON number")
        return es_number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_ser(v, f"{path}[{i}]") for i, v in enumerate(value)) + "]"
    if isinstance(value, dict):
        items = []
        for k in value:
            if not isinstance(k, str):
                raise JCSError(f"{path}: property name {k!r} is not a string")
        for k in sorted(value, key=_utf16_key):
            items.append(_string(k) + ":" + _ser(value[k], f"{path}.{k}"))
        return "{" + ",".join(items) + "}"
    raise JCSError(f"{path}: {type(value).__name__} is not JSON")


def jcs_dumps(value: Any) -> str:
    """RFC 8785 canonical text."""
    return _ser(value, "$")


def jcs_bytes(value: Any) -> bytes:
    """RFC 8785 canonical UTF-8 bytes: what gets hashed or signed."""
    return jcs_dumps(value).encode("utf-8")
