# modifiedreport.py
import requests
from bs4 import BeautifulSoup
import json, re, csv, time, datetime as dt
from typing import Optional, List, Dict, Tuple

# ---------------------- Config ----------------------
DEFAULT_DB_PATH = "modify1.json"   # local DB JSON (optional, used first)
DEFAULT_CVE_LIST = "cves.txt"      # lines: CVE-YYYY-NNNN[,YYYY-MM-DD]
DELAY   = 0.5                      # polite delay between live fetches
TIMEOUT = 25

# Minimum number of CVE-backed records to print when running with no args
MIN_DEFAULT_RESULTS = 30

# If cves.txt missing, we’ll use this fallback list:
CVE_FALLBACK_LINES = [
    "CVE-2025-26264",
    "CVE-2025-12345,2025-07-08",
    "CVE-2024-9999",
]

# ---------------------- HTTP session ----------------------
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Version/18.0 Safari/605.1.15")
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
})

# ---------------------- Endpoints ------------------------
EDB_HOME         = "https://www.exploit-db.com/"
EDB_DETAIL_FMT   = "https://www.exploit-db.com/exploits/{id}"
EDB_RAW_FMT      = "https://www.exploit-db.com/raw/{id}"
EDB_SEARCH_Q     = "https://www.exploit-db.com/search?q={q}"
EDB_SEARCH_CVE   = "https://www.exploit-db.com/search?cve={cve}"
CSV_URL          = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
RAW_BASE_GITLAB  = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/"

# ---------------------- Regex helpers --------------------
HDR = {
    "title"           : re.compile(r"^\s*#\s*((?:Exploit\s*)?Title)\s*:?\s*(.+)$", re.I),
    "author"          : re.compile(r"^\s*#\s*((?:Exploit\s*)?Author)\s*:?\s*(.+)$", re.I),
    "date"            : re.compile(r"^\s*#\s*(Date)\s*:?\s*(.+)$", re.I),
    "vendor_homepage" : re.compile(r"^\s*#\s*(Vendor\s*Homepage)\s*:?\s*(.+)$", re.I),
    "software_link"   : re.compile(r"^\s*#\s*(Software\s*Link)\s*:?\s*(.+)$", re.I),
    "version"         : re.compile(r"^\s*#\s*(Version)\s*:?\s*(.+)$", re.I),
    "tested_on"       : re.compile(r"^\s*#\s*(Tested\s*on)\s*:?\s*(.+)$", re.I),
    "cve"             : re.compile(r"^\s*#\s*(CVE(?:\s*IDs?)?|CVE\s*ID)\s*:?\s*(.+)$", re.I),
    "poc"             : re.compile(r"^\s*#\s*(PoC|POC)\s*:?\s*(.+)$", re.I),
}
CVE_TOKEN  = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
URL_TOKEN  = re.compile(r"https?://[^\s\)\]]+")
SECTION_HEADINGS = {
    "requirements": re.compile(r"^\s*requirements\s*$", re.I),
    "impact": re.compile(r"^\s*impact\s*$", re.I),
    "poc": re.compile(r"^\s*(poc|proof\s*of\s*concept|steps\s*(to)?\s*reproduce)\s*$", re.I),
}
BULLET = re.compile(r"^\s*([-*•]|--)\s+(.*)$")

# ---------------------- Utils ----------------------------
def http_get_text(url: str) -> Optional[str]:
    try:
        r = SESSION.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.content.decode(r.apparent_encoding or "utf-8", errors="ignore")
        return None
    except Exception:
        return None

def parse_date_to_iso(s: Optional[str]) -> Optional[str]:
    if not s: return None
    s = s.strip()
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", s)
    if m: return m.group(1)
    for fmt in ("%d-%b-%Y", "%d-%B-%Y", "%b %d, %Y", "%B %d, %Y",
                "%d/%m/%Y", "%Y/%m/%d", "%d.%m.%Y"):
        try:
            return dt.datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except Exception:
            pass
    m = re.search(r"(\d{4})[-/\.](\d{1,2})[-/\.](\d{1,2})", s)
    if m:
        y, mo, d = map(int, m.groups())
        try:
            return dt.date(y, mo, d).isoformat()
        except Exception:
            return None
    return None

def dd_mmm_from_iso(iso: Optional[str]) -> Optional[str]:
    if not iso: return None
    y, m, d = map(int, iso.split("-"))
    return f"{d:02d}-{dt.date(y, m, d).strftime('%b').upper()}-{y}"

def split_tested_on(s: str) -> List[str]:
    parts = re.split(r"\s*\|\s*|,|;|/| or ", s, flags=re.I)
    return [p.strip() for p in parts if p.strip()]

def norm_type(s: Optional[str]) -> Optional[str]:
    if not s: return None
    t = s.strip().lower()
    if t in {"webapps", "web apps", "web application", "web applications"}:
        return "webapps"
    return t

# ---------------------- CSV index / latest IDs -----------
def load_csv_index() -> Dict[int, dict]:
    txt = http_get_text(CSV_URL) or ""
    idx: Dict[int, dict] = {}
    if not txt: return idx
    for row in csv.DictReader(txt.splitlines()):
        try:
            if (row.get("file") or "").startswith("exploits/"):
                idx[int(row["id"])] = row
        except Exception:
            continue
    return idx

def latest_ids_from_csv(n: int) -> List[int]:
    idx = load_csv_index()
    if not idx: return []
    return sorted(idx.keys(), reverse=True)[:max(1, n)]

# ---------------------- Parsers (raw/html) --------------------
def parse_raw_headers(text: str) -> dict:
    out = {
        "Exploit Title": None, "_title_label": None,
        "Exploit Author": None, "_author_label": None,
        "date": None,
        "vendor_homepage": None, "software_link": None, "version": None,
        "tested_on_raw": None, "cve_list": None, "poc": None, "body_start": 0,
    }
    lines = text.splitlines()
    body_start = 0
    for i, line in enumerate(lines[:300]):
        matched = False
        m = HDR["title"].match(line)
        if m:
            out["_title_label"] = m.group(1).strip()
            out["Exploit Title"] = (m.group(2) or "").strip()
            matched = True
        m = HDR["author"].match(line)
        if m:
            out["_author_label"] = m.group(1).strip()
            out["Exploit Author"] = (m.group(2) or "").strip()
            matched = True
        m = HDR["date"].match(line)
        if m:
            out["date"] = (m.group(2) or "").strip()
            matched = True
        for key in ["vendor_homepage","software_link","version","tested_on","cve","poc"]:
            if matched: break
            mm = HDR.get(key, None).match(line) if HDR.get(key) else None
            if not mm: continue
            val = (mm.group(2) or "").strip()
            if key == "vendor_homepage": out["vendor_homepage"] = val
            elif key == "software_link": out["software_link"] = val
            elif key == "version": out["version"] = val
            elif key == "tested_on": out["tested_on_raw"] = val
            elif key == "cve":
                cves = [c.upper() for c in CVE_TOKEN.findall(val or "")]
                out["cve_list"] = sorted(set(cves))
            elif key == "poc": out["poc"] = val
            matched = True
        if not matched and not line.strip().startswith("#"):
            body_start = i
            break
    out["body_start"] = body_start
    if not out.get("cve_list"):
        cves = [c.upper() for c in CVE_TOKEN.findall(text or "")]
        if cves: out["cve_list"] = sorted(set(cves))
    return out

def parse_body_sections_from_raw(text: str, body_start: int) -> dict:
    body = "\n".join(text.splitlines()[body_start:]).strip() if text else ""
    lines = [ln.rstrip() for ln in body.splitlines()]
    blocks, buf = [], []
    for ln in lines:
        if ln.strip() == "":
            if buf:
                blocks.append("\n".join(buf).strip()); buf = []
        else:
            buf.append(ln)
    if buf: blocks.append("\n".join(buf).strip())

    overview = []
    sections = {"requirements": [], "impact": [], "poc_text": None}
    current = None

    def is_heading(text: str) -> Optional[str]:
        t = text.strip()
        for key, pat in SECTION_HEADINGS.items():
            if pat.match(t): return key
        return None

    for blk in blocks:
        key = is_heading(blk)
        if key:
            current = key; continue
        if current is None:
            overview.append(blk); continue
        for subln in blk.splitlines():
            m = BULLET.match(subln)
            if m:
                sections.setdefault(current, [])
                sections[current].append(m.group(2).strip())
            else:
                if current == "poc":
                    sections["poc_text"] = (sections.get("poc_text") or "")
                    sections["poc_text"] = (sections["poc_text"] + ("\n" if sections["poc_text"] else "") + subln.strip()).strip()
                else:
                    if subln.strip():
                        sections.setdefault(current, [])
                        sections[current].append(subln.strip())

    links = sorted(set(URL_TOKEN.findall(body or "")))
    return {
        "overview": "\n\n".join(overview).strip() if overview else None,
        "requirements": sections.get("requirements") or [],
        "impact": sections.get("impact") or [],
        "poc_text": sections.get("poc_text"),
        "links": links,
    }

def parse_detail_html(html: str) -> dict:
    soup = BeautifulSoup(html or "", "lxml")
    meta = {"h1_title": None, "author": None, "platform": None, "type": None,
            "cve_from_html": [], "verified": None, "date_iso": None}
    h1 = soup.find("h1")
    if h1:
        meta["h1_title"] = (h1.get_text(" ", strip=True) or "").strip()

    labels = {}
    for row in soup.select("table tr"):
        th = row.find("th"); td = row.find("td")
        if th and td:
            labels[th.get_text(strip=True).lower()] = td.get_text(" ", strip=True)

    if not labels:
        for dl in soup.select("dl"):
            for dt_tag, dd_tag in zip(dl.find_all("dt"), dl.find_all("dd")):
                labels[dt_tag.get_text(strip=True).lower()] = dd_tag.get_text(" ", strip=True)

    def pick(key: str):
        for k, v in labels.items():
            if key in k: return v.strip()
        return None

    meta["author"]   = pick("author")
    meta["platform"] = pick("platform")
    meta["type"]     = pick("type")
    meta["verified"] = pick("verified")
    cve_val = pick("cve")
    if cve_val:
        meta["cve_from_html"] = sorted(set(c.upper() for c in CVE_TOKEN.findall(cve_val)))
    meta["date_iso"] = parse_date_to_iso(pick("date") or pick("published"))
    return meta

def parse_body_sections_from_html(html: str) -> dict:
    soup = BeautifulSoup(html or "", "lxml")
    def para_texts(node):
        out=[]
        for p in node.find_all(["p","li"]):
            if p.find_parent(["pre","code"]): continue
            t = p.get_text(" ", strip=True)
            if t: out.append(t)
        return out

    overview, requirements, impact = [], [], []
    poc_text = None
    text_blocks = para_texts(soup)

    def pull(heads):
        for h in soup.find_all(re.compile("^h[1-6]$")):
            lab=(h.get_text(" ", strip=True) or "").lower()
            if any(k in lab for k in heads):
                buf=[]
                for sib in h.find_all_next():
                    if sib.name and re.match(r"^h[1-6]$", sib.name): break
                    if sib.name in ("p","li") and not sib.find_parent(["pre","code"]):
                        t=sib.get_text(" ", strip=True)
                        if t: buf.append(t)
                return buf
        return []
    req=pull(["requirement"]); imp=pull(["impact"]); poc=pull(["poc","proof of concept","steps to reproduce"])
    if req: requirements=req
    if imp: impact=imp
    if poc: poc_text="\n".join(poc)

    if text_blocks:
        for t in text_blocks:
            if any(k in t.lower() for k in ["requirements","impact","proof of concept","steps to reproduce"]):
                continue
            overview.append(t)
        if not overview and text_blocks:
            overview=text_blocks[:3]
    links = sorted(set(URL_TOKEN.findall(" ".join(text_blocks) if text_blocks else "")))
    return {
        "overview": "\n\n".join(overview).strip() if overview else None,
        "requirements": requirements,
        "impact": impact,
        "poc_text": poc_text,
        "links": links,
    }

# ---------------------- Build record / normalize ----------------------
def normalize_record(edb_id: int, csv_row: Optional[dict], raw: dict, html_meta: dict, body: dict) -> dict:
    raw_title  = raw.get("Exploit Title")
    html_title = html_meta.get("h1_title")
    csv_title  = (csv_row.get("description") if csv_row else None)
    chosen_title = raw_title or html_title or csv_title

    raw_author  = raw.get("Exploit Author")
    html_author = html_meta.get("author")
    csv_author  = (csv_row.get("author") if csv_row else None)
    chosen_author = raw_author or html_author or csv_author

    date_iso = html_meta.get("date_iso") or parse_date_to_iso(raw.get("date") or "")

    platform = html_meta.get("platform") or (csv_row.get("platform") if csv_row else None)
    etype    = html_meta.get("type") or (csv_row.get("type") if csv_row else None)
    poc      = raw.get("poc")
    vendor_homepage = raw.get("vendor_homepage")
    software_link   = raw.get("software_link")
    version         = raw.get("version")
    tested_on = split_tested_on(raw["tested_on_raw"]) if raw.get("tested_on_raw") else []
    cves = raw.get("cve_list") or html_meta.get("cve_from_html") or []
    cves = sorted(set(cves))

    rec = {
        "Exploit Title": chosen_title,
        "Exploit Author": chosen_author,
        "cve": cves,
        "id": str(edb_id),
        "platform": platform,
        "poc": poc,
        "port": (csv_row.get("port") if csv_row else "") if csv_row else "",
        "published_date": dd_mmm_from_iso(date_iso) if date_iso else None,
        "published_date_iso": date_iso,
        "software_link": software_link,
        "source": "Exploit-DB",
        "tested_on": tested_on,
        "type": etype,
        "url": EDB_DETAIL_FMT.format(id=edb_id),
        "vendor_homepage": vendor_homepage,
        "verified": html_meta.get("verified"),
        "version": version,
        "details": {
            "overview": body.get("overview"),
            "requirements": body.get("requirements") or [],
            "impact": body.get("impact") or [],
            "poc_text": body.get("poc_text"),
            "links": body.get("links") or [],
        }
    }
    if isinstance(rec.get("type"), str):
        t = rec["type"].strip().lower()
        rec["type"] = "webapps" if t in {"webapps","web apps","web application","web applications"} else t
    return rec

def force_defaults(rec: dict) -> dict:
    core_str = ["Exploit Title","Exploit Author","platform","software_link","type",
                "vendor_homepage","version","published_date","published_date_iso"]
    if not rec.get("Exploit Title") and not rec.get("Exploit Author") and not (rec.get("details") or {}).get("overview"):
        for k in core_str:
            if rec.get(k) in (None, ""):
                rec[k] = "NA"
    d = rec.setdefault("details", {})
    if d.get("overview") in (None, ""): d["overview"] = "NA"
    if d.get("poc_text") in (None, ""): d["poc_text"] = "NA"
    if d.get("requirements") is None: d["requirements"] = []
    if d.get("impact") is None: d["impact"] = []
    if d.get("links") is None: d["links"] = []
    if rec.get("cve") is None: rec["cve"] = []
    if rec.get("tested_on") is None: rec["tested_on"] = []
    if rec.get("port") is None: rec["port"] = ""
    return rec

def build_record_for_id(edb_id: int, csv_index: Optional[Dict[int, dict]]) -> dict:
    raw_txt = http_get_text(EDB_RAW_FMT.format(id=edb_id))
    row = csv_index.get(edb_id) if csv_index else None
    if not raw_txt and row and row.get("file"):
        raw_txt = http_get_text(RAW_BASE_GITLAB + row["file"]) or ""
    parsed_raw = parse_raw_headers(raw_txt or "")
    body_raw  = parse_body_sections_from_raw(raw_txt or "", parsed_raw.get("body_start", 0))
    html = http_get_text(EDB_DETAIL_FMT.format(id=edb_id)) or ""
    meta_html = parse_detail_html(html) if html else {}
    if not body_raw.get("overview") and html:
        body_html = parse_body_sections_from_html(html)
        for k in ["overview","requirements","impact","poc_text","links"]:
            if not body_raw.get(k):
                body_raw[k] = body_html.get(k)
    rec = normalize_record(edb_id, row, parsed_raw, meta_html, body_raw)
    return force_defaults(rec)

# ---------------------- Search helpers ----------------------
def collect_ids_from_listing(listing_url: str, pages: int = 1) -> List[int]:
    ids: List[int] = []
    url = listing_url
    for _ in range(max(1, pages)):
        html = http_get_text(url) or ""
        if not html: break
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            m = re.search(r"/exploits/(\d+)", a["href"])
            if m:
                ids.append(int(m.group(1)))
        next_href = None
        for a in soup.find_all("a", href=True):
            label = (a.get_text(strip=True) or "").upper()
            if label == "NEXT" or a.get("rel") == ["next"]:
                next_href = a["href"]; break
        if not next_href: break
        if next_href.startswith("/"):
            url = EDB_HOME.rstrip("/") + next_href
        elif next_href.startswith("http"):
            url = next_href
        else:
            url = EDB_HOME.rstrip("/") + "/" + next_href.lstrip("/")
    seen, uniq = set(), []
    for i in ids:
        if i not in seen:
            uniq.append(i); seen.add(i)
    return uniq

def scrape_and_store_to_json(url: str, output_filename: str = "report.json", pages: int = 1, count: int = 30):
    ids = collect_ids_from_listing(url, pages=pages)
    if not ids:
        ids = latest_ids_from_csv(max(count, pages*30))
        if not ids:
            print("[error] Could not collect IDs from listing or CSV.")
            return
    csv_index = load_csv_index()
    results = []
    for edb_id in ids:
        rec = build_record_for_id(edb_id, csv_index)
        results.append(rec)
        time.sleep(DELAY)
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"✅ Wrote {len(results)} records to {output_filename}")

def search_ids_for_cve_live(cve: str) -> List[int]:
    """Try Exploit-DB search endpoints to find exploit IDs for a CVE."""
    ids: List[int] = []
    for url in (EDB_SEARCH_CVE.format(cve=cve), EDB_SEARCH_Q.format(q=cve)):
        html = http_get_text(url)
        if not html:
            continue
        for m in re.finditer(r"/exploits/(\d+)", html):
            ids.append(int(m.group(1)))
        time.sleep(0.2)
    seen, uniq = set(), []
    for i in ids:
        if i not in seen:
            uniq.append(i); seen.add(i)
    return uniq

# ---------------------- DB helpers + API -----------------
def _load_db(db_path: str) -> List[dict]:
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []

def _records_for_cve_in_db(cve_id: str, db_path: str) -> List[dict]:
    want = (cve_id or "").strip().upper()
    if not want:
        return []
    recs = []
    for r in _load_db(db_path):
        cves = [c.upper() for c in (r.get("cve") or [])]
        if want in cves:
            recs.append(r)
    return recs

def API(cve_id: str, date_iso: Optional[str] = None,
        db_path: str = DEFAULT_DB_PATH,
        live_fallback: bool = True) -> Optional[List[dict]]:
    """
    API('CVE-2025-12345', '2025-07-08'):
      1) Look up CVE in local DB; if date provided, require published_date_iso match.
      2) If not found and live_fallback=True, search Exploit-DB live and return full records.
      Returns list of full records on success; None if no match.
    """
    want = (cve_id or "").strip().upper()
    if not want:
        return None

    # 1) DB lookup
    recs = _records_for_cve_in_db(want, db_path)
    if date_iso:
        date_iso = parse_date_to_iso(date_iso) or date_iso
        recs = [r for r in recs if (r.get("published_date_iso") or "") == (date_iso or "")]
    if recs:
        return recs

    # 2) Live fallback
    if not live_fallback:
        return None

    ids = search_ids_for_cve_live(want)
    if not ids:
        return None

    csv_index = load_csv_index()
    out: List[dict] = []
    for edb_id in ids:
        rec = build_record_for_id(edb_id, csv_index)
        cves_upper = [c.upper() for c in (rec.get("cve") or [])]
        if want not in cves_upper:
            continue
        if date_iso:
            d = rec.get("published_date_iso") or ""
            if (parse_date_to_iso(d) or d) != date_iso:
                continue
        out.append(rec)
        time.sleep(DELAY)
    return out or None

# ---------------------- Fill to at least N CVE records -----------------
def fetch_latest_cve_records(min_needed: int,
                             exclude_ids: Optional[set] = None,
                             exclude_cves: Optional[set] = None) -> List[dict]:
    """
    Pull recent Exploit-DB items (via CSV index), build full records,
    and return those that have at least one CVE. Skips IDs/CVEs in exclude sets.
    """
    exclude_ids = exclude_ids or set()
    exclude_cves = set([c.upper() for c in (exclude_cves or set())])

    # Grab a generous slice of latest IDs so we can filter to those with CVEs
    ids = latest_ids_from_csv(max(300, min_needed * 15))
    csv_index = load_csv_index()
    out: List[dict] = []

    for edb_id in ids:
        if edb_id in exclude_ids:
            continue
        rec = build_record_for_id(edb_id, csv_index)
        cves = [c.upper() for c in (rec.get("cve") or [])]
        if not cves:
            continue
        if exclude_cves and all(c in exclude_cves for c in cves):
            # All CVEs are already represented; skip
            continue
        out.append(rec)
        exclude_ids.add(edb_id)
        for c in cves:
            exclude_cves.add(c)
        if len(out) >= min_needed:
            break
        time.sleep(DELAY)
    return out

# ---------------------- No-arg default runner ------------
def _parse_cve_line(line: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Accepts:
      CVE-YYYY-NNNN
      CVE-YYYY-NNNN,YYYY-MM-DD
    Returns (cve, date_or_None) or (None, None).
    """
    if not line.strip():
        return (None, None)
    upper = line.strip().upper()
    cve_m = CVE_TOKEN.search(upper)
    if not cve_m:
        return (None, None)
    cve = cve_m.group(0)
    parts = [p.strip() for p in line.split(",")]
    date_iso = parse_date_to_iso(parts[1]) if len(parts) > 1 and parts[1] else None
    return (cve, date_iso)

def _load_cve_queries_from_file(path: str) -> List[Tuple[str, Optional[str]]]:
    import pathlib
    p = pathlib.Path(path)
    if not p.exists():
        return []
    out: List[Tuple[str, Optional[str]]] = []
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        cve, date_iso = _parse_cve_line(raw)
        if cve:
            out.append((cve, date_iso))
    return out

def _fallback_queries() -> List[Tuple[str, Optional[str]]]:
    out: List[Tuple[str, Optional[str]]] = []
    for raw in CVE_FALLBACK_LINES:
        cve, date_iso = _parse_cve_line(raw)
        if cve:
            out.append((cve, date_iso))
    return out

def default_run(db_path: str = DEFAULT_DB_PATH, cve_list_path: str = DEFAULT_CVE_LIST) -> int:
    """
    Run with no args:
      - Read CVEs from cves.txt (or fallback list)
      - For each CVE[,date], print full JSON record(s) if found (DB or live), else print 'null'
      - Then top up with the latest Exploit-DB CVE-backed records until at least MIN_DEFAULT_RESULTS are printed
    """
    queries = _load_cve_queries_from_file(cve_list_path)
    if not queries:
        queries = _fallback_queries()

    printed_count = 0
    seen_ids: set = set()
    seen_cves: set = set()

    # 1) Process requested CVEs first
    for cve, date_iso in queries:
        recs = API(cve, date_iso, db_path=db_path, live_fallback=True)
        if not recs:
            print("null")
            printed_count += 1
            continue
        # print all records for that CVE (dedup by id)
        for r in recs:
            rid = int(r.get("id") or 0) if (r.get("id") and str(r.get("id")).isdigit()) else r.get("id")
            if rid in seen_ids:
                continue
            print(json.dumps(r, ensure_ascii=False, indent=2))
            printed_count += 1
            seen_ids.add(rid)
            for c in (r.get("cve") or []):
                seen_cves.add(c.upper())

    # 2) If we haven't printed at least MIN_DEFAULT_RESULTS items, top up with latest CVE-backed exploits
    if printed_count < MIN_DEFAULT_RESULTS:
        need = MIN_DEFAULT_RESULTS - printed_count
        fillers = fetch_latest_cve_records(need, exclude_ids=seen_ids, exclude_cves=seen_cves)
        for r in fillers:
            print(json.dumps(r, ensure_ascii=False, indent=2))
        printed_count += len(fillers)

    return 0

# ---------------------- CLI ------------------------------
if __name__ == "__main__":
    import argparse, sys
    if len(sys.argv) == 1:
        sys.exit(default_run())

    ap = argparse.ArgumentParser(
        description="Exploit-DB → JSON with exact 'Exploit Title'/'Exploit Author' keys + full details"
    )
    sub = ap.add_subparsers(dest="cmd")

    # scrape subcommand (optional: build your local DB)
    scrape = sub.add_parser("scrape", help="Scrape listing/CSV and write JSON DB")
    scrape.add_argument("--url", type=str, default=EDB_HOME, help="Listing URL (default: Exploit-DB home)")
    scrape.add_argument("--pages", type=int, default=1, help="How many listing pages to traverse")
    scrape.add_argument("--count", type=int, default=30, help="How many items to fetch if listing empty (CSV fallback)")
    scrape.add_argument("--out", type=str, default=DEFAULT_DB_PATH, help="Output JSON file")

    # api subcommand (single CVE, optional date; DB + live fallback)
    api = sub.add_parser("api", help="Lookup CVE (DB first, then live search); prints full records or null")
    api.add_argument("--cve", required=True, type=str, help="CVE ID (e.g., CVE-2025-26264)")
    api.add_argument("--date", type=str, help="Optional ISO date (YYYY-MM-DD)")
    api.add_argument("--db", type=str, default=DEFAULT_DB_PATH, help="Path to JSON DB")
    api.add_argument("--no-live", action="store_true", help="Disable live fallback (DB only)")

    args = ap.parse_args()

    if args.cmd == "scrape":
        scrape_and_store_to_json(args.url, output_filename=args.out, pages=args.pages, count=args.count)
        sys.exit(0)

    if args.cmd == "api":
        recs = API(args.cve, args.date, db_path=args.db, live_fallback=not args.no_live)
        if not recs:
            print("null")
        elif len(recs) == 1:
            print(json.dumps(recs[0], ensure_ascii=False, indent=2))
        else:
            print(json.dumps(recs, ensure_ascii=False, indent=2))
        sys.exit(0)

    ap.print_help()
    sys.exit(1)
