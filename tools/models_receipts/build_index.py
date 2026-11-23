import json, hashlib, os, shutil, time
SRC = "C:/SZL/edge-debug/ou30_full_scan.json"
PKG = "C:/SZL/edge-debug/ou30_pkg"
RDIR = "C:/SZL/kimi-charter/runtime/receipts"
TDIR = "C:/SZL/kimi-charter/runtime/transcripts"
SCAN_NOW = "2026-11-22T23:08:16Z"
CORE_FAMS = {"szl", "khipu", "chaski", "absrl", "doctrine", "brain", "chakana", "oac", "quant", "receiptagent"}
RANK = {"FULL_SHOWCASE": 0, "SHOWCASE_SEED": 1, "TEMPLATE_BASELINE": 2, "THIN": 3, "NO_README": 4, "READ_ERR": 4}
def fam(mid):
    n = (mid.split("/")[-1]).lower()
    return n.split("-")[0]
def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()
scan = json.loads(open(SRC, encoding="utf-8").read())
rows = scan["rows"]
models = []
for r in rows:
    f = fam(r["model"])
    m = {"model": r["model"], "family": f, "core": f in CORE_FAMS, "tier": r["tier"]}
    for k in ("len", "receipt_hits", "receipts_sect", "hashes", "measured", "unavailable", "err"):
        if k in r: m[k] = r[k]
    models.append(m)
models.sort(key=lambda m: (not m["core"], RANK.get(m["tier"], 9), m["model"]))
gap = {}
for m in models:
    key = ("core_" if m["core"] else "other_") + m["tier"]
    gap[key] = gap.get(key, 0) + 1
fam_counts = {}
for m in models:
    fam_counts[m["family"]] = fam_counts.get(m["family"], 0) + 1
index_canon = json.dumps(models, sort_keys=True, separators=(",", ":"))
index = {
  "schema_version": "ou30-models-receipts-index-v1",
  "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "scan_receipt": {"file": "ou30_full_scan.json", "executed_utc": SCAN_NOW, "source": "huggingface.co/api/models?author=SZLHOLDINGS + per-model README resolve, read-only"},
  "council_ruling": "quad ou30 seats 2026-11-22: kimi (GOVERNING, ADAPT) + astra-o (ADOPT) + claude rail (UNVERIFIED_COMMUNITY_RAIL, ADOPT, advisory) + sol61 rail (UNVERIFIED_COMMUNITY_RAIL, ADOPT, advisory)",
  "totals": {"models": len(models)},
  "tier_counts": scan["tier_counts"],
  "gap_manifest": gap,
  "family_counts": fam_counts,
  "integrity_sha256": sha(index_canon),
  "integrity_note": "sha256 over canonical JSON of the models array (sort_keys, compact). Recompute to verify no bandaid edits.",
  "tranche_1_order_rule": "core families first, ordered by measured completeness then model name (tier rank then alpha); recency not in scan, kept honest",
  "models": models,
}
for sub in ("", "receipts", "transcripts", "snippets"):
    os.makedirs(os.path.join(PKG, sub), exist_ok=True)
open(os.path.join(PKG, "ou30_models_receipts_index_v1.json"), "w", encoding="utf-8").write(json.dumps(index, indent=1))
shutil.copyfile(SRC, os.path.join(PKG, "ou30_full_scan.json"))
for s in ("kimi", "astra", "claude", "sol61"):
    rn = os.path.join(RDIR, "ou30_seat_%s_20261122_receipt.json" % s)
    tn = os.path.join(TDIR, "ou30_seat_%s_20261122_transcript.md" % s)
    if os.path.exists(rn): shutil.copyfile(rn, os.path.join(PKG, "receipts", "ou30_seat_%s_20261122_receipt.json" % s))
    if os.path.exists(tn): shutil.copyfile(tn, os.path.join(PKG, "transcripts", "ou30_seat_%s_20261122_transcript.md" % s))
tier_notes = {
  "FULL_SHOWCASE": "Already meets the measured bar (szl-khipu anatomy family: receipts sections + sha anchors + MEASURED/UNAVAILABLE labels). Package below is a confirmation record, not an edit.",
  "SHOWCASE_SEED": "Has receipts sections but below bar (missing sha anchors or measured labels or size). Upgrade path below.",
  "TEMPLATE_BASELINE": "Uniform honest ~1.6KB template card. No receipts sections, no sha anchors. Upgrade path below.",
  "THIN": "Card below even the template baseline. Upgrade path below.",
}
n = 0
manifest = []
for m in models:
    if not m["core"]: continue
    name = m["model"].split("/")[-1]
    fn = "".join(c if c.isalnum() or c in "-._" else "_" for c in name) + ".snippet.md"
    body = []
    body.append("# Receipts Showcase proposal for " + m["model"] + "\n")
    body.append("status: PROPOSE_ONLY_UNSIGNED (model card edits gated on owner signature mint; this file is the proposal, published first in wave-logs as the receipt)")
    body.append("schema_version: ou30-showcase-v1")
    body.append("audit_source: SZLHOLDINGS/wave-logs mesh/2026-11-22/ouroboros/ou30-models-receipts-tranche1/")
    body.append("audit_receipt: ou30_full_scan.json (executed " + SCAN_NOW + ") + ou30_models_receipts_index_v1.json\n")
    body.append("## Measured card state (ou30 full scan, read-only)\n")
    for k, lab in (("tier", "card_tier_measured"), ("len", "readme_bytes"), ("receipt_hits", "receipt_mentions"), ("receipts_sect", "receipts_sections"), ("hashes", "sha256_anchors"), ("measured", "measured_labels"), ("unavailable", "unavailable_labels")):
        if k in m: body.append("- " + lab + ": " + str(m[k]))
    body.append("- " + tier_notes.get(m["tier"], ""))
    body.append("\n## Receipts manifest (UNFILLED)\n")
    body.append("Per-receipt identifiers are not present on this card today. Under fail-closed doctrine they must be minted from the receipts ledger (training runs, PR merges, wave-log commits); never inferred, never fabricated.")
    body.append("- receipt[1..n]: UNFILLED\n")
    body.append("## Upgrade path to FULL_SHOWCASE (council bar, quad ruling 2026-11-22)\n")
    body.append("1. Receipts manifest with sha256 anchors (szl-khipu anatomy verbatim, ADAPT per governing seat: machine-readable YAML block, schema version, scan timestamp, verification command, explicit NOT_SCANNED state)")
    body.append("2. Honest MEASURED / UNAVAILABLE labels")
    body.append("3. wave-logs linkage")
    body.append("4. Entry in ou30_models_receipts_index_v1.json (this package, already present)\n")
    text = "\n".join(body)
    esha = sha(text)
    snippet = text + "entry_sha256: " + esha + "\n"
    open(os.path.join(PKG, "snippets", fn), "w", encoding="utf-8").write(snippet)
    manifest.append({"model": m["model"], "file": "snippets/" + fn, "tier": m["tier"], "entry_sha256": esha})
    n += 1
open(os.path.join(PKG, "snippets_manifest.json"), "w", encoding="utf-8").write(json.dumps({"schema_version": "ou30-snippets-manifest-v1", "count": n, "tranche": "tranche-1 core families", "entries": manifest}, indent=1))
print("GEN_DONE core_snippets=%d total_models=%d gap=%s" % (n, len(models), json.dumps(gap)))
