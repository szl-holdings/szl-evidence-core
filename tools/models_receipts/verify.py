import json, hashlib, os, sys, time
PKGD = sys.argv[1] if len(sys.argv) > 1 else "C:/SZL/edge-debug/ou30_pkg"
def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()
def fail(msg):
    out = {"action": "ou30_verify_receipts", "verdict": "FAIL", "reason": msg, "utc_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "pkg_dir": PKGD}
    try:
        open(os.path.join(PKGD, "ou30_verifier_receipt.json"), "w", encoding="utf-8").write(json.dumps(out, indent=1))
    except Exception:
        pass
    print("VERIFIER_FAIL " + msg)
    sys.exit(3)
idxp = os.path.join(PKGD, "ou30_models_receipts_index_v1.json")
if not os.path.exists(idxp): fail("index missing")
idx = json.loads(open(idxp, encoding="utf-8").read())
models = idx["models"]
canon = json.dumps(models, sort_keys=True, separators=(",", ":"))
if sha(canon) != idx.get("integrity_sha256"): fail("index integrity_sha256 mismatch (bandaid edit suspected)")
smanp = os.path.join(PKGD, "snippets_manifest.json")
if not os.path.exists(smanp): fail("snippets_manifest missing")
sman = json.loads(open(smanp, encoding="utf-8").read())
if sman.get("count") != len(sman.get("entries", [])): fail("manifest count mismatch")
manifest_by_model = {}
for e in sman["entries"]:
    manifest_by_model[e["model"]] = e
n = 0
for e in sman["entries"]:
    fp = os.path.join(PKGD, e["file"].replace("/", os.sep))
    if not os.path.exists(fp): fail("snippet missing for " + e["model"])
    raw = open(fp, encoding="utf-8").read()
    marker = "entry_sha256: "
    tail = raw[raw.rfind(marker):]
    esha = tail[len(marker):].strip()
    body = raw[:raw.rfind(marker)]
    if sha(body) != e.get("entry_sha256"): fail("manifest hash mismatch for " + e["model"])
    if sha(body) != esha: fail("snippet footer hash mismatch for " + e["model"])
    n += 1
core = [m for m in models if m.get("core")]
missing = [m["model"] for m in core if m["model"] not in manifest_by_model]
if missing: fail("core models without snippet package: " + ",".join(missing[:5]))
tier_ok = {}
for m in models:
    tier_ok[m["tier"]] = tier_ok.get(m["tier"], 0) + 1
if tier_ok != idx.get("tier_counts"): fail("tier counts mismatch vs index")
out = {"action": "ou30_verify_receipts", "verdict": "PASS", "utc_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "pkg_dir": PKGD, "models_indexed": len(models), "snippets_verified": n, "core_models": len(core), "integrity_sha256": idx["integrity_sha256"]}
open(os.path.join(PKGD, "ou30_verifier_receipt.json"), "w", encoding="utf-8").write(json.dumps(out, indent=1))
print("VERIFIER_PASS models=%d snippets=%d core=%d" % (len(models), n, len(core)))
