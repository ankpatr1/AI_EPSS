# demo_latest15.py
import json, re, time, argparse
from datetime import datetime
from typing import Dict, List, Optional
import requests
from bs4 import BeautifulSoup

BASE = "https://www.exploit-db.com"
UA = {"User-Agent": "Mozilla/5.0 (compatible; edb-scraper/1.0)"}

# ---------- your required function ----------
def _(cveid: str, report: str) -> dict:
    """
    Normalize one Exploit-DB item to your schema.
    `report` may be a JSON string OR the raw '# Key: Value' header block.
    """
    DATE_INPUT_FORMATS = [
        "%Y-%m-%d", "%Y.%m.%d", "%d/%m/%Y", "%m/%d/%Y",
        "%d-%m-%Y", "%b %d %Y", "%B %d %Y",
    ]
    CVE_PAT = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

    def parse_date_any(s: Optional[str]) -> Optional[datetime]:
        if not s or not isinstance(s, str): return None
        s = s.strip()
        for fmt in DATE_INPUT_FORMATS:
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                pass
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
            try:
                return datetime.strptime(s, "%Y-%m-%d")
            except ValueError:
                return None
        return None

    def to_iso(dt: Optional[datetime]) -> Optional[str]:
        return dt.strftime("%Y-%m-%d") if dt else None

    def to_dd_mon_yyyy(dt: Optional[datetime]) -> Optional[str]:
        return dt.strftime("%d-%b-%Y").upper() if dt else None

    def clean_cves(items: List[str]) -> List[str]:
        out, seen = [], set()
        for c in items or []:
            if not isinstance(c, str): 
                continue
            c = c.strip().upper()
            if CVE_PAT.match(c) and c not in seen:
                seen.add(c); out.append(c)
        return out

    def as_list(x) -> List[str]:
        if x is None: return []
        if isinstance(x, list):
            return [str(e).strip() for e in x if str(e).strip()]
        if isinstance(x, str):
            parts = re.split(r"\s*\|\s*|,\s*|;\s*", x.strip())
            return [p for p in parts if p]
        return [str(x).strip()]

    def parse_header_block(text: str) -> Dict[str, str]:
        pairs: Dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line.startswith("#"): 
                continue
            m = re.match(r"^\#\s*([^:]+)\s*:\s*(.*)$", line)
            if m:
                pairs[m.group(1).strip()] = m.group(2).strip()
        return pairs

    # ingest
    obj: Dict = {}
    try:
        obj = json.loads(report)
    except json.JSONDecodeError:
        pairs = parse_header_block(report)
        obj = {
            "author": pairs.get("Exploit Author") or pairs.get("Author"),
            "poc": pairs.get("PoC") or pairs.get("POC") or pairs.get("Proof of Concept"),
            "software_link": pairs.get("Software Link"),
            "vendor_homepage": pairs.get("Vendor Homepage"),
            "version": pairs.get("Version"),
            "tested_on": pairs.get("Tested on"),
            "title": pairs.get("Exploit Title"),
            "cve": as_list(pairs.get("CVE")),
            "published_date": pairs.get("Date"),
        }

    # date
    dt = None
    for key in ("published_date", "published_date_iso", "date"):
        if obj.get(key):
            dt = parse_date_any(obj.get(key))
            if dt: break

    # CVEs (ensure cveid is included if valid)
    cves = []
    if isinstance(cveid, str):
        cves.append(cveid)
    if isinstance(obj.get("cve"), list):
        cves.extend(obj.get("cve"))
    cves = clean_cves(cves)

    # exact schema
    return {
        "author": (obj.get("author") or None),
        "cve": cves,
        "id": None,
        "platform": None,
        "poc": (obj.get("poc") or None),
        "port": None,
        "published_date": to_dd_mon_yyyy(dt),
        "published_date_iso": to_iso(dt),
        "software_link": (obj.get("software_link") or None),
        "source": "Exploit-DB",
        "tested_on": as_list(obj.get("tested_on")),
        "title": (obj.get("title") or None),
        "type": None,
        "url": "",
        "vendor_homepage": (obj.get("vendor_homepage") or None),
        "verified": None,
        "version": (obj.get("version") or None),
    }

# ---------- fetch helpers ----------
def http_get(url: str, timeout=25, retries=3, backoff=1.2):
    for i in range(retries):
        try:
            r = requests.get(url, headers=UA, timeout=timeout)
            if r.status_code == 200:
                return r
            if r.status_code in (403,404):
                return None
        except requests.RequestException:
            pass
        time.sleep(min(10, backoff * (i + 1)))
    return None

def page_has_exploit(edb_id: int) -> bool:
    r = http_get(f"{BASE}/exploits/{edb_id}")
    return r is not None

def find_latest_id(upper_guess: int = 80000) -> int:
    # Step down until we hit something, then binary search upward range
    hi = upper_guess
    if not page_has_exploit(hi):
        step = 5000
        while hi > 1000 and not page_has_exploit(hi):
            hi -= step
            step = max(1000, step // 2)
        if hi < 1000:
            hi = 1000

    # binary search between lo..hi to the highest existing id
    lo = 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if page_has_exploit(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo

def extract_header_block_from_html(html: str) -> Optional[str]:
    soup = BeautifulSoup(html, "html.parser")
    # Prefer <pre> blocks containing header lines
    for pre in soup.find_all("pre"):
        t = pre.get_text("\n", strip=False)
        if "# Exploit Title:" in t or "# Vendor Homepage:" in t or "# Tested on:" in t or "# PoC" in t or "# CVE" in t or "# Date" in t:
            return t
    # fallback: sometimes in <code>
    for code in soup.find_all("code"):
        t = code.get_text("\n", strip=False)
        if "# Exploit Title:" in t or "# Vendor Homepage:" in t or "# Tested on:" in t or "# PoC" in t or "# CVE" in t or "# Date" in t:
            return t
    # if nothing, return empty string (your _() handles it)
    return ""

def fetch_normalized_for_latest(n: int) -> List[dict]:
    latest = find_latest_id()
    out: List[dict] = []
    eid = latest
    while eid > 0 and len(out) < n:
        url = f"{BASE}/exploits/{eid}"
        r = http_get(url)
        if r:
            header = extract_header_block_from_html(r.text) or ""
            # pass empty CVE id; the function will pick CVEs from header if present
            rec = _("", header)
            out.append(rec)
        eid -= 1
        time.sleep(0.4)  # be polite
    return out

# ---------- CLI ----------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch latest Exploit-DB items and output normalized JSONL.")
    parser.add_argument("--latest", type=int, default=15, help="How many latest exploits to fetch (default: 15)")
    parser.add_argument("--out", help="Write JSONL to this file (default: stdout)")
    args = parser.parse_args()

    items = fetch_normalized_for_latest(args.latest)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            for rec in items:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    else:
        for rec in items:
            print(json.dumps(rec, ensure_ascii=False))
