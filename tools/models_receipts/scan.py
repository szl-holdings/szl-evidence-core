import json, time, urllib.request, re, sys
def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "szl-ou30-readonly"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")
models = json.loads(get("https://huggingface.co/api/models?author=SZLHOLDINGS&limit=1000&full=false"))
names = sorted(m.get("modelId") or m.get("id") for m in models)
rows = []
for i, mid in enumerate(names):
    row = {"model": mid}
    try:
        rd = get("https://huggingface.co/" + mid + "/resolve/main/README.md")
        row["len"] = len(rd)
        row["receipt_hits"] = rd.lower().count("receipt")
        row["receipts_sect"] = len(re.findall(r"(?im)^#+.*receipt", rd))
        row["hashes"] = len(re.findall(r"\b[0-9a-f]{40,64}\b", rd))
        row["measured"] = len(re.findall(r"(?i)MEASURED", rd))
        row["unavailable"] = len(re.findall(r"(?i)UNAVAILABLE", rd))
        row["lanelogs"] = len(re.findall(r"(?i)lanelog", rd))
        row["wave_logs"] = len(re.findall(r"(?i)wave-logs", rd))
    except urllib.error.HTTPError as e:
        row["err"] = e.code
    except Exception as e:
        row["err"] = repr(e)[:100]
    rows.append(row)
    if i % 50 == 0:
        open("C:/SZL/edge-debug/ou30_full_scan.json.partial", "w", encoding="utf-8").write(json.dumps({"done": i, "rows": rows}, indent=0))
        print("PROGRESS", i, flush=True)
    time.sleep(0.15)
def tier(r):
    if "err" in r:
        return "NO_README" if r.get("err") == 404 else "READ_ERR"
    if r["len"] >= 5000 and r["receipts_sect"] >= 1 and r["hashes"] >= 2 and r["measured"] >= 1:
        return "FULL_SHOWCASE"
    if r["len"] >= 1200 and r["receipts_sect"] >= 1:
        return "SHOWCASE_SEED"
    if r["receipt_hits"] >= 3:
        return "TEMPLATE_BASELINE"
    return "THIN"
for r in rows:
    r["tier"] = tier(r)
counts = {}
for r in rows:
    counts[r["tier"]] = counts.get(r["tier"], 0) + 1
out = {"now": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "total": len(rows), "tier_counts": counts, "rows": rows}
open("C:/SZL/edge-debug/ou30_full_scan.json", "w", encoding="utf-8").write(json.dumps(out, indent=1))
full = [r["model"] for r in rows if r["tier"] == "FULL_SHOWCASE"]
seed = [r["model"] for r in rows if r["tier"] == "SHOWCASE_SEED"]
print("FULL_SCAN_DONE total=%d counts=%s full=%s seed=%s" % (len(rows), json.dumps(counts), json.dumps(full), json.dumps(seed[:15])))
