# crowdsec_cti_pull_hardcoded.py
# WARNING: hardcoded API key below. Do NOT commit this file. Rotate the key after testing.

import os, time, json, argparse
from datetime import datetime
import pandas as pd
import requests

# Use env var if set; else fall back to your key
API_KEY = os.getenv("CROWDSEC_CTI_API_KEY") or "1Un1bPHrKK5oJxSFbNR0Q3bDVyNN4A6M6wAXmoe9"

BASE = "https://cti.api.crowdsec.net"
SMOKE_SINGLE = f"{BASE}/v2/smoke/1.1.1.1"
SEARCH_URL   = f"{BASE}/v2/smoke/search"   # correct dataset search route

DEFAULT_QUERY = 'classifications.classifications.name:"profile:web_hosting" AND (reputation:malicious OR reputation:suspicious)'

def pick_items(payload):
    if isinstance(payload, dict):
        for k in ("items","ips","data","results"):
            v = payload.get(k)
            if isinstance(v, list):
                return v
    if isinstance(payload, list):
        return payload
    return []

def fetch_all(api_key, query, since, page_size, max_pages, sleep):
    headers = {"x-api-key": api_key}
    pg = 1
    frames = []
    while pg <= max_pages:
        params = {"q": query, "since": since, "page": pg, "page_size": page_size}
        r = requests.get(SEARCH_URL, headers=headers, params=params, timeout=60)
        if r.status_code == 401:
            raise SystemExit("401 Unauthorized: bad/missing CROWDSEC_CTI_API_KEY")
        if r.status_code == 403:
            raise SystemExit("403 Forbidden: key/plan may not allow this search endpoint")
        if r.status_code == 429:
            time.sleep(1.5); continue
        r.raise_for_status()
        rows = pick_items(r.json())
        if not rows:
            break
        frames.append(pd.json_normalize(rows))
        if len(rows) < page_size:  # last page
            break
        pg += 1
        time.sleep(sleep)
    if not frames:
        return pd.DataFrame(), pg
    return pd.concat(frames, ignore_index=True), pg

def ensure_dir(p):
    os.makedirs(p, exist_ok=True); return p

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", default=DEFAULT_QUERY)
    ap.add_argument("--since", default="30d")
    ap.add_argument("--page-size", type=int, default=10)
    ap.add_argument("--max-pages", type=int, default=1000)
    ap.add_argument("--out", default="./out")
    ap.add_argument("--prefix", default="crowdsec_web_hosting")
    ap.add_argument("--skip-selfcheck", action="store_true")
    args = ap.parse_args()

    api_key = API_KEY
    if not api_key:
        raise SystemExit("No API key. Set CROWDSEC_CTI_API_KEY or edit this file.")

    if not args.skip_selfcheck:
        t = requests.get(SMOKE_SINGLE, headers={"x-api-key": api_key}, timeout=30)
        if t.status_code != 200:
            raise SystemExit(f"Self-check failed: HTTP {t.status_code}")

    df, pages_used = fetch_all(api_key, args.query, args.since, args.page_size, args.max_pages, sleep=0.3)
    out_dir = ensure_dir(args.out)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    csv_path  = os.path.join(out_dir, f"{args.prefix}_{ts}.csv")
    md_path   = os.path.join(out_dir, f"{args.prefix}_{ts}.md")
    json_path = os.path.join(out_dir, f"{args.prefix}_{ts}.json")
    master_csv = os.path.join(out_dir, f"{args.prefix}_MASTER.csv")
    delta_csv  = os.path.join(out_dir, f"{args.prefix}_DELTA_{ts}.csv")

    if df.empty:
        print("No results for the given query/time range."); return

    df.to_csv(csv_path, index=False)
    try:
        df.head(50).to_markdown(md_path, index=False)  # needs 'tabulate' package
    except Exception as e:
        print(f"Markdown export skipped: {e}")
    with open(json_path, "w") as f:
        json.dump({"query": args.query, "since": args.since, "pages_fetched": pages_used,
                   "data": df.to_dict(orient="records")}, f)

    try:
        if os.path.exists(master_csv):
            old = pd.read_csv(master_csv)
            combo = pd.concat([old, df], ignore_index=True)
        else:
            combo = df.copy()
        subset = ["ip"] if "ip" in combo.columns else combo.columns.tolist()
        before = len(combo)
        combo = combo.drop_duplicates(subset=subset)
        after = len(combo)
        combo.to_csv(master_csv, index=False)

        # delta: newly added rows vs previous MASTER
        if 'old' in locals() and not old.empty:
            if "ip" in df.columns and "ip" in old.columns:
                prev = set(old["ip"].dropna().astype(str))
                delta_df = df[~df["ip"].astype(str).isin(prev)].copy()
            else:
                delta_df = pd.concat([df, old]).drop_duplicates(keep=False)
            if not delta_df.empty:
                delta_df.to_csv(delta_csv, index=False)
                print(f"Delta rows: {len(delta_df)} -> {delta_csv}")
            else:
                print("No new rows vs previous MASTER.")
        print(f"MASTER deduped: {before} -> {after} rows -> {master_csv}")
    except Exception as e:
        print(f"MASTER/DELTA update skipped: {e}")

    print("Saved:")
    print(" -", csv_path)
    print(" -", md_path)
    print(" -", json_path)

if __name__ == "__main__":
    main()
