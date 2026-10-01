"""Three cross-organ receipt primitives, tested rather than assumed."""
import json, hashlib, math

print("="*74)
print("1. allow_nan: 34 of 35 implementations leave it at the default")
obj = {"score": float("nan"), "run": "r1"}
emitted = json.dumps(obj, sort_keys=True, separators=(",", ":"))
print(f"   json.dumps default emits: {emitted}")
try:
    json.loads(emitted, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    print("   re-parsed by a strict JSON reader: OK")
except ValueError as exc:
    print(f"   a STRICT JSON reader REJECTS it: {exc!r}")
print("   -> NaN is not valid JSON. A receipt containing it hashes fine locally")
print("      and becomes unverifiable by any conforming external verifier.")
try:
    json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)
except ValueError as exc:
    print(f"   allow_nan=False refuses at emit time: {exc}")

print()
print("="*74)
print("2. hash algorithm: 22 sha256 vs 13 sha3_256 on the SAME canonical bytes")
body = json.dumps({"a": 1}, sort_keys=True, separators=(",", ":")).encode()
h2 = hashlib.sha256(body).hexdigest()
h3 = hashlib.sha3_256(body).hexdigest()
print(f"   sha256   {h2}")
print(f"   sha3_256 {h3}")
print(f"   identical: {h2 == h3}")
print("   -> A chain written by a torch-ext kernel (sha3) cannot be verified by")
print("      a service verifier (sha256). Neither is wrong; they are incompatible,")
print("      and nothing in the receipt body declares which was used.")

print()
print("="*74)
print("3. separators: 3 of 35 omit them, changing the bytes that get hashed")
o = {"b": 2, "a": 1}
with_sep = json.dumps(o, sort_keys=True, separators=(",", ":"))
without  = json.dumps(o, sort_keys=True)
print(f"   with separators:    {with_sep!r}")
print(f"   without separators: {without!r}")
print(f"   sha256 differs: {hashlib.sha256(with_sep.encode()).hexdigest()[:16]}"
      f" vs {hashlib.sha256(without.encode()).hexdigest()[:16]}")
print("   -> Same object, same sort_keys, DIFFERENT digest. Cross-organ")
print("      verification fails on whitespace alone.")

print()
print("="*74)
print("4. ensure_ascii: all 35 rely on the default (True), which is the safe one")
u = {"name": "Küllinchu \u2713"}
a = json.dumps(u, sort_keys=True, separators=(",", ":"))
n = json.dumps(u, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
print(f"   default (escaped): {a}")
print(f"   ensure_ascii=False: {n}")
print(f"   byte lengths {len(a.encode())} vs {len(n.encode())} -> digests differ:"
      f" {hashlib.sha256(a.encode()).hexdigest()[:12]} vs {hashlib.sha256(n.encode()).hexdigest()[:12]}")
print("   -> Consistent today by luck, not by contract. One explicit")
print("      ensure_ascii=False anywhere silently forks every digest.")
