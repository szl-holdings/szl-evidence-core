"""Do the estate's Λ implementations agree on the SAME input?

Λ is doctrine: non-compensatory, so a single zeroed axis must drive the whole
result to zero. If one implementation floors the input instead, a zero axis
produces a NON-ZERO Λ and the veto is silently lost. That is not a style
difference; it is a governance defect.
"""
import math

# a11oy/payloads/lambda_gate.py: clamps each axis to a 1e-6 floor
def lambda_a11oy(axes, weights):
    log = 0.0; wsum = 0.0
    for k, w in weights.items():
        v = max(1e-6, min(1.0, max(0.0, axes[k])))   # <-- the floor
        log += w * math.log(v); wsum += w
    return math.exp(log / wsum) if wsum else 0.0

# szl-atelier / szl-khipu: any non-positive axis is a hard zero veto
def lambda_veto(axes, weights):
    xs = [axes[k] for k in weights]; ws = [weights[k] for k in weights]
    if any(x <= 0.0 for x in xs): return 0.0
    if abs(math.fsum(ws) - 1.0) >= 1e-9: return 0.0
    return math.exp(math.fsum(w * math.log(x) for x, w in zip(xs, ws)))

W = {"a1": 0.25, "a2": 0.25, "a3": 0.25, "a4": 0.25}
cases = {
    "all axes healthy":      {"a1": 0.9,  "a2": 0.9,  "a3": 0.9,  "a4": 0.9},
    "ONE AXIS ZEROED":       {"a1": 0.9,  "a2": 0.9,  "a3": 0.9,  "a4": 0.0},
    "two axes zeroed":       {"a1": 0.9,  "a2": 0.9,  "a3": 0.0,  "a4": 0.0},
    "one axis near-zero":    {"a1": 0.9,  "a2": 0.9,  "a3": 0.9,  "a4": 1e-9},
}
FLOOR = 0.90  # vsp-otel LAMBDA_FLOOR
print(f"{'case':24s} {'floored':>12s} {'veto':>10s} {'delta':>10s}  verdict")
for name, axes in cases.items():
    a = lambda_a11oy(axes, W); v = lambda_veto(axes, W)
    verdict = "AGREE" if abs(a - v) < 1e-12 else "*** DISAGREE ***"
    print(f"{name:24s} {a:12.9f} {v:10.6f} {abs(a-v):10.6f}  {verdict}")
print()
z = {"a1": 0.9, "a2": 0.9, "a3": 0.9, "a4": 0.0}
a = lambda_a11oy(z, W)
print(f"With one axis fully zeroed, the floored implementation returns Lambda={a:.9f}")
print(f"  non-compensatory doctrine requires exactly 0.0")
print(f"  the zero-axis veto is LOST: {a:.9f} != 0.0 -> {a > 0}")
print(f"  gate at ADMIT>=0.5 would still refuse here ({a:.6f} < 0.5), so the")
print(f"  defect is latent, not currently exploitable at that threshold.")
