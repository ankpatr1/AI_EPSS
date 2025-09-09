#!/usr/bin/env python3
import re, csv, time, argparse, sys
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"\b(?!(?:\d{1,3}\.){3}\d{1,3})[a-z0-9-]+(?:\.[a-z0-9-]+)+\b", re.I)
SEEN_RE = re.compile(r"\b\d+\s+(?:second|minute|hour|day|week|month|year)s?\s+ago\b", re.I)
CLS_RE = re.compile(r"\b(\d+)\s+Classifications?\b", re.I)
BEH_RE = re.compile(r"\b(\d+)\s+Behaviors?\b", re.I)

def build_driver(headless: bool):
    opts = Options()
    if headless:
        opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1400,1000")
    service = Service(ChromeDriverManager().install())
    return webdriver.Chrome(service=service, options=opts)

def wait_for_login_and_results(driver, url, timeout=180):
    driver.get(url)
    # Wait until we see either “Malicious IP” or “Suspicious IP” somewhere on the page
    WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located(
            (By.XPATH, "//*[contains(., 'Malicious IP') or contains(., 'Suspicious IP')]")
        )
    )

def scroll_collect(driver, want=30, max_scrolls=30, pause=1.0):
    """Scrolls and collects candidate card elements."""
    seen_ids = set()
    cards = []
    last_h = 0
    for s in range(max_scrolls):
        # Collect all block-ish elements; we’ll filter by text content
        blocks = driver.find_elements(By.XPATH, "//div[.//text()]")
        for b in blocks:
            try:
                txt = b.text.strip()
            except Exception:
                continue
            if not txt:
                continue
            if ("Malicious IP" not in txt) and ("Suspicious IP" not in txt):
                continue
            if not IP_RE.search(txt):
                continue
            # Use the IP as a lightweight ID to avoid duplicates
            ip = IP_RE.search(txt).group(0)
            if ip in seen_ids:
                continue
            # Heuristic: real cards have both rep label and a “ago” timestamp line
            if not SEEN_RE.search(txt):
                continue
            seen_ids.add(ip)
            cards.append((ip, txt))
            if len(cards) >= want:
                return cards

        # scroll
        driver.execute_script("window.scrollBy(0, document.body.scrollHeight);")
        time.sleep(pause)
        new_h = driver.execute_script("return document.body.scrollHeight;")
        if new_h == last_h:
            break
        last_h = new_h
    return cards

def parse_card_text(txt: str):
    ip = (IP_RE.search(txt).group(0) if IP_RE.search(txt) else "")
    rep = "Malicious" if "Malicious IP" in txt else ("Suspicious" if "Suspicious IP" in txt else "")
    seen = SEEN_RE.search(txt)
    seen_ago = seen.group(0) if seen else ""
    host = ""
    # Prefer the first hostname that is not the IP and not the ASN
    candidates = HOST_RE.findall(txt)
    if candidates:
        host = candidates[0]

    # Country and ASN are typically like: "• USA • UNIFIEDLAYER-AS-1"
    # Heuristic: take the last ALL-CAPS token of length 2-3 as country code
    country = ""
    tokens = [t.strip() for t in re.split(r"[•|·|-]+", txt)]
    caps = [t for t in tokens if re.fullmatch(r"[A-Z]{2,3}", t)]
    if caps:
        country = caps[-1]

    # ASN: take the last token that looks like an ASN-ish name (contains -AS- or endswith -AS)
    asn = ""
    as_like = [t for t in tokens if re.search(r"-AS\b|-AS-", t)]
    if as_like:
        asn = as_like[-1].strip()

    cls = CLS_RE.search(txt)
    beh = BEH_RE.search(txt)
    cls_n = int(cls.group(1)) if cls else 0
    beh_n = int(beh.group(1)) if beh else 0

    return {
        "ip": ip,
        "reputation": rep,
        "seen_ago": seen_ago,
        "hostname": host,
        "country": country,
        "asn": asn,
        "classifications": cls_n,
        "behaviors": beh_n,
    }

def main():
    ap = argparse.ArgumentParser(description="Scrape CrowdSec Console CTI list to CSV (logged-in browser).")
    ap.add_argument("--url", required=True, help="CTI search URL from app.crowdsec.net (the page in your screenshot).")
    ap.add_argument("--max", type=int, default=30, help="Max cards to capture (default: 30).")
    ap.add_argument("--headless", action="store_true", help="Run Chrome headless (works only if already logged in).")
    ap.add_argument("--out", default="crowdsec_console_latest.excel", help="Output excel filename.")
    args = ap.parse_args()

    driver = build_driver(headless=args.headless)
    try:
        print("Opening browser… log in if prompted. Waiting for results…")
        wait_for_login_and_results(driver, args.url)
        print("Collecting cards…")
        cards = scroll_collect(driver, want=args.max)
        print(f"Found {len(cards)} cards; parsing…")

        rows = [parse_card_text(txt) for _, txt in cards]

        # Write CSV
        with open(args.out, "w", newline="") as f:
            w = csv.DictWriter(
                f,
                fieldnames=[
                    "ip","reputation","seen_ago","hostname","country","asn","classifications","behaviors"
                ],
            )
            w.writeheader()
            for r in rows:
                w.writerow(r)

        print(f"Saved {len(rows)} rows → {args.out}")
    finally:
        # keep the window a second so you can see it finished (non-headless)
        if not args.headless:
            time.sleep(1.0)
        driver.quit()

if __name__ == "__main__":
    main()
