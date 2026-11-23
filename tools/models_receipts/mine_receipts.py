import json, os, re, time, hashlib, urllib.request
from pathlib import Path
from huggingface_hub import HfApi
OUT = "C:/SZL/edge-debug/ou30_model_receipt_mining.json"
PKGD = "C:/SZL/edge-debug/ou30_pkg"
token = Path("C:/Users/steph/.cache/huggingface/token").read_text(encoding="utf-8").strip()
api = HfApi(token=token)
idx = json.loads(open(os.path.join(PKGD, "ou30_models_receipts_index_v1.json"), encoding="utf-8").read())
models = [m["model"] for m in idx["models"]]
core = [m["model"] for m in idx["models"] if m.get("core")]
core_names = set(core)
all_bare = {}
for m in models:
    all_bare[m.split("/")[-1].lower()] = m
cands = []
try:
    for d in api.list_datasets(author="SZLHOLDINGS"):
        did = getattr(d, "id", None) or d
        if re.search(r"ledger|receipt|run|wave|train|eval|energy|evidence|salad|frontier", str(did), re.I):
            cands.append(str(did))
except Exception as e:
    print("LIST_ERR " + repr(e)[:150])
cands = sorted(set(cands))[:15]
print("MINING_DATASETS " + json.dumps(cands), flush=True)
results = {}
stats = {"datasets": len(cands), "files_scanned": 0, "bytes_scanned": 0, "receipt_hits": 0}
for ds in cands:
    try:
        tree = api.list_repo_tree(ds, repo_type="dataset", recursive=True)
        entries = [(e.path, e.size) for e in tree if str(e.path).endswith((".json", ".jsonl", ".md"))]
        entries = [(p, s) for p, s in entries if (s or 0) < 2000000][:250]
    except Exception as e:
        print("TREE_ERR " + ds + " " + repr(e)[:100], flush=True)
        continue
    for path, size in entries:
        url = "https://huggingface.co/datasets/" + ds + "/resolve/main/" + path
        try:
            raw = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "szl-ou30-mine"}), timeout=30).read().decode("utf-8", "replace")
        except Exception as e:
            continue
        stats["files_scanned"] += 1
        stats["bytes_scanned"] += len(raw)
        file_sha = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        low = raw.lower()
        matched = set()
        for bare, full in all_bare.items():
            if bare in low or full.lower() in low:
                matched.add(full)
        for m in matched:
            lines = [ln for ln in raw.splitlines() if m.split("/")[-1].lower() in ln.lower() or m.lower() in ln.lower()]
            for ln in lines[:6]:
                rec = {"dataset": ds, "file": path, "file_sha256": file_sha, "model": m, "evidence_line": ln[:400]}
                results.setdefault(m, []).append(rec)
                stats["receipt_hits"] += 1
        time.sleep(0.05)
    print("MINED " + ds + " cumulative_models_with_hits=" + str(len(results)), flush=True)
out = {"now": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "stats": stats, "datasets_mined": cands, "per_model": results}
open(OUT, "w", encoding="utf-8").write(json.dumps(out, indent=1))
core_hit = [m for m in core if m in results]
print("MINING_DONE models_with_receipts=%d core_with_receipts=%d/%d datasets=%d files=%d hits=%d" % (len(results), len(core_hit), len(core), len(cands), stats["files_scanned"], stats["receipt_hits"]))
