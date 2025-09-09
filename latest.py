#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Exploit-DB → JSON (last N days), with BeautifulSoup for HTML details
+ rich parsing of the raw text to extract Overview / Requirements / Impact / PoC.

Usage:
  python3 edb_bs_last_15_days_sections.py --days 15 --out edb_last_15_days.json
"""

import argparse
import csv
import datetime as dt
import json
import re
import time
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup

CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
RAW_BASE_GITLAB = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
EDB_DETAIL_FMT = "https://www.exploit-db.com/exploits/{id}"
EDB_RAW_FMT = "https://www.exploit-db.com/raw/{id}"

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Version/18.0 Safari/605.1.15")
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": UA})

# ----------------------- regex helpers -----------------------
HEADER_PATTERNS = {
    "title": re.compile(r"^\s*#\s*(Exploit\s*Title)\s*:?\s*(.+)$", re.I),
    "date": re.compile(r"^\s*#\s*(Date)\s*:?\s*(.+)$", re.I),
    "author": re.compile(r"^\s*#\s*(Exploit\s*Author|Author)\s*:?\s*(.+)$", re.I),
    "vendor_homepage": re.compile(r"^\s*#\s*(Vendor\s*Homepage)\s*:?\s*(.+)$", re.I),
    "software_link": re.compile(r"^\s*#\s*(Software\s*Link)\s*:?\s*(.+)$", re.I),
    "version": re.compile(r"^\s*#\s*(Version)\s*:?\s*(.+)$", re.I),
    "tested_on": re.compile(r"^\s*#\s*(Tested\s*on)\s*:?\s*(.+)$", re.I),
    "cve": re.compile(r"^\s*#\s*(CVE(?:\s*IDs?)?|CVE\s*ID)\s*:?\s*(.+)$", re.I),
    "poc": re.compile(r"^\s*#\s*(PoC|POC)\s*:?\s*(.+)$", re.I),
}
CVE_TOKEN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
URL_TOKEN = re.compile(r"https?://[^\s\)]+")

SECTION_HEADINGS = {
    "requirements": re.compile(r"^\s*requirements\s*$", re.I),
    "impact": re.compile(r"^\s*impact\s*$", re.I),
    "poc": re.compile(r"^\s*(poc|proof\s*of\s*concept|steps\s*(to)?\s*reproduce)\s*$", re.I),
    # you can add more synonyms here if you encounter other styles
}

BULLET = re.compile(r"^\s*([-*•]|--)\s+(.*)$")

# ----------------------- tiny utils -----------------------
def clean(s: Optional[str]) -> Optional[str]:
    if s is None: return None
    s = s.strip()
    return s or None

def to_iso(date_str: str) -> Optional[str]:
    if not date_str: return None
    s = date_str.strip()
    fmts = ["%Y-%m-%d", "%d-%b-%Y", "%d-%B-%Y", "%d/%m/%Y", "%Y/%m/%d", "%d.%m.%Y"]
    for f in fmts:
        try:
            return dt.datetime.strptime(s, f).strftime("%Y-%m-%d")
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

def to_dd_mmm_yyyy(iso: Optional[str]) -> Optional[str]:
    if not iso: return None
    y, m, d = map(int, iso.split("-"))
    return f"{d:02d}-{dt.date(y, m, d).strftime('%b').upper()}-{y}"

def split_tested_on(s: str) -> List[str]:
    parts = re.split(r"\s*\|\s*|,|;|/| or ", s, flags=re.I)
    return [p.strip() for p in parts if p.strip()]

def http_get_text(url: str, timeout: float = 25.0) -> Optional[str]:
    try:
        r = SESSION.get(url, timeout=timeout)
        if r.status_code == 200:
            return r.content.decode(r.apparent_encoding or "utf-8", errors="ignore")
        return None
    except Exception:
        return None

# ----------------------- CSV + HTML/RAW parsing -----------------------
def load_csv_rows() -> List[dict]:
    txt = http_get_text(CSV_URL)
    if not txt:
        raise SystemExit("Failed to download files_exploits.csv.")
    rows = []
    rdr = csv.DictReader(txt.splitlines())
    for row in rdr:
        if (row.get("file") or "").startswith("exploits/"):
            rows.append(row)
    return rows

def parse_raw_headers(text: str) -> Tuple[dict, int]:
    """
    Parse header key:value lines (starting with '# ...') and return:
      - dict of extracted header fields
      - index of the first non-header line (start of body)
    """
    out = {
        "title": None, "date": None, "author": None,
        "vendor_homepage": None, "software_link": None, "version": None,
        "tested_on_raw": None, "cve_list": None, "poc": None,
    }
    lines = text.splitlines()
    body_start = 0
    for i, line in enumerate(lines[:300]):
        matched = False
        for key, pat in HEADER_PATTERNS.items():
            m = pat.match(line)
            if not m: continue
            matched = True
            val = clean(m.group(2))
            if key == "title": out["title"] = val
            elif key == "date": out["date"] = val
            elif key == "author": out["author"] = val
            elif key == "vendor_homepage": out["vendor_homepage"] = val
            elif key == "software_link": out["software_link"] = val
            elif key == "version": out["version"] = val
            elif key == "tested_on": out["tested_on_raw"] = val
            elif key == "cve":
                cves = CVE_TOKEN.findall(val or "")
                out["cve_list"] = sorted(set(c.upper() for c in cves))
            elif key == "poc": out["poc"] = val
        if not matched and line.strip().startswith("#"):
            # A header-ish line we don't recognize; continue scanning
            continue
        if not line.strip().startswith("#"):
            body_start = i
            break

    if not out.get("cve_list"):
        cves = CVE_TOKEN.findall(text)
        if cves: out["cve_list"] = sorted(set(c.upper() for c in cves))

    return out, body_start

def parse_detail_html(html: str) -> dict:
    """Use BeautifulSoup to extract author/platform/type/CVE/verified/title."""
    soup = BeautifulSoup(html, "lxml")
    meta = {"author": None, "platform": None, "type": None,
            "cve_from_html": [], "verified": None, "title_html": None}

    h1 = soup.find("h1")
    if h1: meta["title_html"] = clean(h1.get_text(" ", strip=True))

    labels = {}
    for row in soup.select("table tr"):
        th = row.find("th")
        td = row.find("td")
        if th and td:
            labels[th.get_text(strip=True).lower()] = td.get_text(" ", strip=True)
    if not labels:
        for dl in soup.select("dl"):
            dts = dl.find_all("dt")
            dds = dl.find_all("dd")
            for dt_tag, dd_tag in zip(dts, dds):
                labels[dt_tag.get_text(strip=True).lower()] = dd_tag.get_text(" ", strip=True)

    def pick(key: str) -> Optional[str]:
        for k, v in labels.items():
            if key in k: return clean(v)
        return None

    meta["author"] = pick("author")
    meta["platform"] = pick("platform")
    meta["type"] = pick("type")
    meta["verified"] = pick("verified")
    cve_val = pick("cve")
    if cve_val:
        meta["cve_from_html"] = sorted(set(c.upper() for c in CVE_TOKEN.findall(cve_val)))

    return meta

# ----------------------- body section parsing -----------------------
def parse_body_sections(body: str) -> dict:
    """
    Heuristics to extract:
      - overview (first paragraph(s) before a known section)
      - sections.requirements (list)
      - sections.impact (list)
      - sections.poc_text (string)
      - links (all URLs)
    """
    lines = [ln.rstrip() for ln in body.splitlines()]
    # Normalize empty separators
    blocks = []
    buf: List[str] = []
    for ln in lines:
        if ln.strip() == "":
            if buf:
                blocks.append("\n".join(buf).strip())
                buf = []
        else:
            buf.append(ln)
    if buf:
        blocks.append("\n".join(buf).strip())

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
            current = key
            continue

        if current is None:
            # preface / overview area
            overview.append(blk)
            continue

        # inside a named section: split bullets if present
        for subln in blk.splitlines():
            m = BULLET.match(subln)
            if m:
                sections.setdefault(current, [])
                sections[current].append(m.group(2).strip())
            else:
                # non-bullet text: treat PoC as free text; others append as item
                if current == "poc":
                    sections["poc_text"] = (sections.get("poc_text") or "")
                    sections["poc_text"] = (sections["poc_text"] + ("\n" if sections["poc_text"] else "") + subln.strip()).strip()
                else:
                    if subln.strip():
                        sections.setdefault(current, [])
                        sections[current].append(subln.strip())

    # Links: collect from the entire body
    links = sorted(set(URL_TOKEN.findall(body or "")))

    return {
        "overview": "\n\n".join(overview).strip() if overview else None,
        "requirements": sections.get("requirements") or [],
        "impact": sections.get("impact") or [],
        "poc_text": sections.get("poc_text"),
        "links": links,
    }

# ----------------------- normalization + report -----------------------
def normalize(row: dict, raw_headers: dict, html_meta: dict, body_sections: dict) -> dict:
    edb_id = str(row.get("id") or "").strip() or None
    date_src = clean(row.get("date")) or clean(raw_headers.get("date"))
    date_iso = to_iso(date_src) if date_src else None

    title = clean(raw_headers.get("title")) or clean(html_meta.get("title_html")) or clean(row.get("description"))
    author = clean(raw_headers.get("author")) or clean(html_meta.get("author")) or clean(row.get("author"))
    platform = clean(html_meta.get("platform")) or clean(row.get("platform"))
    etype = clean(html_meta.get("type")) or clean(row.get("type"))

    vendor_homepage = clean(raw_headers.get("vendor_homepage"))
    software_link = clean(raw_headers.get("software_link"))
    version = clean(raw_headers.get("version"))
    poc = clean(raw_headers.get("poc"))
    verified = clean(html_meta.get("verified"))

    tested_on: List[str] = []
    if raw_headers.get("tested_on_raw"):
        tested_on = split_tested_on(raw_headers["tested_on_raw"])

    cve_list = raw_headers.get("cve_list") or html_meta.get("cve_from_html") or []
    cve_list = sorted(set(cve_list))

    return {
        # core fields from your schema
        "author": author,
        "cve": cve_list,
        "id": edb_id,
        "platform": platform,
        "poc": poc,
        "port": clean(row.get("port")),
        "published_date": to_dd_mmm_yyyy(date_iso) if date_iso else None,
        "published_date_iso": date_iso,
        "software_link": software_link,
        "source": "Exploit-DB",
        "tested_on": tested_on,
        "title": title,
        "type": etype,
        "url": EDB_DETAIL_FMT.format(id=edb_id) if edb_id else None,
        "vendor_homepage": vendor_homepage,
        "verified": verified,
        "version": version,

        # rich body extraction
        "content": {
            "overview": body_sections.get("overview"),
            "requirements": body_sections.get("requirements") or [],
            "impact": body_sections.get("impact") or [],
            "poc_text": body_sections.get("poc_text"),
            "links": body_sections.get("links") or [],
        },
    }

# ---------- EXACT SIGNATURE YOU ASKED FOR ----------
def build_report_factory(fields: dict):
    """
    Returns a function with EXACT signature:

        def build_report(cveid: str, report: str) -> dict
    """
    def build_report(cveid: str, report: str) -> dict:
        cves = list(fields.get("cve") or [])
        if cveid:
            cid = cveid.upper().strip()
            if cid and cid not in cves:
                cves = [cid] + cves
        return {
            # keys placed first as in your snippet
            "date": fields.get("published_date"),
            "id": fields.get("id"),
            # full payload
            "author": fields.get("author"),
            "cve": cves,
            "platform": fields.get("platform"),
            "poc": fields.get("poc"),
            "port": fields.get("port"),
            "published_date": fields.get("published_date"),
            "published_date_iso": fields.get("published_date_iso"),
            "software_link": fields.get("software_link"),
            "source": report,  # e.g., "Exploit-DB"
            "tested_on": fields.get("tested_on") or [],
            "title": fields.get("title"),
            "type": fields.get("type"),
            "url": fields.get("url"),
            "vendor_homepage": fields.get("vendor_homepage"),
            "verified": fields.get("verified"),
            "version": fields.get("version"),
            "content": fields.get("content") or {
                "overview": None, "requirements": [], "impact": [], "poc_text": None, "links": []
            },
        }
    return build_report
# ---------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Exploit-DB scraper (last N days) with section parsing")
    ap.add_argument("--days", type=int, default=15, help="How many days back (default: 15)")
    ap.add_argument("--out", type=str, default="edb_last_15_days.json", help="Output JSON file")
    ap.add_argument("--delay", type=float, default=0.5, help="Delay between requests (sec)")
    ap.add_argument("--max", type=int, default=0, help="Max items (0 = all within window)")
    args = ap.parse_args()

    cutoff = (dt.date.today() - dt.timedelta(days=max(1, args.days))).isoformat()

    rows = load_csv_rows()
    rows = [r for r in rows if (r.get("date") and r["date"] >= cutoff)]
    rows.sort(key=lambda r: (r["date"], int(r.get("id") or 0)), reverse=True)
    if args.max and args.max > 0:
        rows = rows[:args.max]

    results: List[dict] = []
    for row in rows:
        edb_id = row["id"]

        # 1) raw text (prefer /raw/<id>; fall back to gitlab file path)
        raw_txt = http_get_text(EDB_RAW_FMT.format(id=edb_id))
        if not raw_txt:
            raw_txt = http_get_text(RAW_BASE_GITLAB + row["file"]) or ""

        raw_headers, body_start = parse_raw_headers(raw_txt or "")
        body_text = ""
        if raw_txt and body_start is not None:
            body_text = "\n".join(raw_txt.splitlines()[body_start:]).strip()
        body_sections = parse_body_sections(body_text or "")

        # 2) detail HTML parsed via BeautifulSoup
        html = http_get_text(EDB_DETAIL_FMT.format(id=edb_id)) or ""
        html_meta = parse_detail_html(html) if html else {}

        # merge & normalize
        fields = normalize(row, raw_headers, html_meta, body_sections)

        # call the EXACT signature function per record
        chosen_cve = (fields.get("cve") or [""])[0]
        report_fn = build_report_factory(fields)
        results.append(report_fn(chosen_cve, "Exploit-DB"))

        time.sleep(max(0.0, args.delay))

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"✅ Wrote {len(results)} records (last {args.days} day(s)) to {args.out}")

if __name__ == "__main__":
    main()
