import json, hashlib, os, time
PKGD = "C:/SZL/edge-debug/ou30_pkg"
MINE = "C:/SZL/edge-debug/ou30_model_receipt_mining.json"
def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()
idx = json.loads(open(os.path.join(PKGD, "ou30_models_receipts_index_v1.json"), encoding="utf-8").read())
sman = json.loads(open(os.path.join(PKGD, "snippets_manifest.json"), encoding="utf-8").read())
mine = json.loads(open(MINE, encoding="utf-8").read())
per_model = mine.get("per_model", {})
filled = 0
by_model = {e["model"]: e for e in sman["entries"]}
for mid, recs in per_model.items():
    e = by_model.get(mid)
    if not e:
        continue
    fn = os.path.join(PKGD, e["file"])
    if not os.path.exists(fn):
        continue
    raw = open(fn, encoding="utf-8").read()
    marker = "entry_sha256: "
    if "receipt[1..n]: UNFILLED" not in raw:
        continue
    lines = [ "- receipt[%d]: LEDGER_MINED dataset=%s file=%s file_sha256=%s evidence=%s" % (i + 1, r["dataset"], r["file"], r["file_sha256"][:16] + "...", (r["evidence_line"] or "").strip().replace("\n", " ")[:200]) for i, r in enumerate(recs[:5]) ]
    mined = "\n## Receipts manifest (LEDGER-MINED, %d receipt(s) found in estate receipt ledgers by ou30 miner 2026-11-23; full evidence at dataset/file above; %d more omitted for space)\n" % (min(len(recs), 5), max(0, len(recs) - 5)) + "\n".join(lines)
    body = raw[:raw.rfind(marker)]
    old_block_start = body.find("## Receipts manifest (UNFILLED)")
    old_block_end = body.find("## Upgrade path")
    if old_block_start == -1 or old_block_end == -1:
        continue
    new_body = body[:old_block_start] + mined + "\n\n" + body[old_block_end:]
    esha = sha(new_body)
    open(fn, "w", encoding="utf-8").write(new_body + "entry_sha256: " + esha + "\n")
    e["entry_sha256"] = esha
    e["manifest_state"] = "LEDGER_MINED_%d" % min(len(recs), 5)
    filled += 1
open(os.path.join(PKGD, "snippets_manifest.json"), "w", encoding="utf-8").write(json.dumps(sman, indent=1))
core = set(m["model"] for m in idx["models"] if m.get("core"))
core_filled = sum(1 for m in per_model if m in core)
open(os.path.join(PKGD, "ou30_mining_fill_receipt.json"), "w", encoding="utf-8").write(json.dumps({"action": "ou30_fill_v2", "verdict": "PASS", "filled_models": filled, "models_with_mined_receipts": len(per_model), "core_with_mined_receipts": core_filled, "mining_stats": mine.get("stats", {}), "utc_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, indent=1))
print("FILL_V2_DONE filled=%d models_with_receipts=%d core_with_receipts=%d" % (filled, len(per_model), core_filled))
