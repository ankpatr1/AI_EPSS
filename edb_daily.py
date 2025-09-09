# edb_daily.py
import re, csv, argparse, datetime as dt, pathlib
from zoneinfo import ZoneInfo
import feedparser

FEED_URL = "https://www.exploit-db.com/rss.xml"  # Exploit-DB RSS

def edb_id_from_link(link: str):
    m = re.search(r"/exploits/(\d+)", link or "")
    return m.group(1) if m else ""

def find_cve(text: str):
    m = re.search(r"CVE-\d{4}-\d{4,7}", text or "", flags=re.I)
    return (m.group(0) if m else "").upper()

def to_dt_utc(entry):
    t = entry.get("published_parsed")
    if not t:
        return None
    # published_parsed is a time.struct_time in UTC for Exploit-DB feed
    return dt.datetime(*t[:6], tzinfo=dt.timezone.utc)

def collect(entries, cutoff_utc):
    rows = []
    for e in entries:
        pub = to_dt_utc(e)
        if not pub or pub < cutoff_utc:
            continue
        link = e.get("link", "")
        title = (e.get("title") or "").strip()
        rows.append({
            "published_utc": pub.astimezone(dt.timezone.utc).isoformat(timespec="seconds"),
            "title": title,
            "edb_id": edb_id_from_link(link),
            "cve": find_cve(title),
            "link": link,
        })
    return rows

def main():
    ap = argparse.ArgumentParser()
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--today", action="store_true", help="Since midnight America/New_York")
    grp.add_argument("--hours", type=int, default=24, help="Rolling window in hours (default: 24)")
    ap.add_argument("--fallback", type=int, default=10, help="If empty window, include latest N items")
    ap.add_argument("--outdir", default=".", help="Output directory")
    args = ap.parse_args()

    now_utc = dt.datetime.now(dt.timezone.utc)

    if args.today:
        ny = ZoneInfo("America/New_York")
        start_today_ny = dt.datetime.now(ny).replace(hour=0, minute=0, second=0, microsecond=0)
        cutoff_utc = start_today_ny.astimezone(dt.timezone.utc)
        window_label = f"since {start_today_ny.strftime('%Y-%m-%d')} 00:00 America/New_York"
    else:
        cutoff_utc = now_utc - dt.timedelta(hours=args.hours)
        window_label = f"last {args.hours} hours (UTC)"

    feed = feedparser.parse(FEED_URL)
    entries = getattr(feed, "entries", [])
    rows = collect(entries, cutoff_utc)

    used_fallback = False
    if not rows and args.fallback > 0:
        used_fallback = True
        # take latest N regardless of time
        latest = []
        for e in entries[:args.fallback]:
            pub = to_dt_utc(e) or now_utc
            link = e.get("link", "")
            title = (e.get("title") or "").strip()
            latest.append({
                "published_utc": pub.astimezone(dt.timezone.utc).isoformat(timespec="seconds"),
                "title": title,
                "edb_id": edb_id_from_link(link),
                "cve": find_cve(title),
                "link": link,
            })
        rows = latest

    stamp = now_utc.strftime("%Y-%m-%d")
    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    out_csv = outdir / f"exploitdb_daily_{stamp}.csv"
    out_md  = outdir / f"exploitdb_daily_{stamp}.md"

    rows_sorted = sorted(rows, key=lambda r: r["published_utc"], reverse=True)

    # CSV
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["published_utc","title","edb_id","cve","link"])
        w.writeheader()
        w.writerows(rows_sorted)

    # Markdown
    with out_md.open("w", encoding="utf-8") as f:
        hdr = f"# Exploit-DB — {window_label} (generated {stamp})\n\n"
        if used_fallback:
            hdr += f"_No new items in window; showing latest {args.fallback} instead._\n\n"
        f.write(hdr)
        for r in rows_sorted:
            tag = f" — {r['cve']}" if r["cve"] else ""
            edb = f"(EDB-{r['edb_id']})" if r["edb_id"] else ""
            f.write(f"- {r['published_utc']}: [{r['title']}]({r['link']}) {edb}{tag}\n")

    print(f"Wrote {out_csv} and {out_md} with {len(rows_sorted)} row(s).")

if __name__ == "__main__":
    main()
