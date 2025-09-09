import requests, sys

def must_smoke_ok(headers):
    test_ip = "1.1.1.1"
    r = requests.get(f"https://cti.api.crowdsec.net/v2/smoke/{test_ip}",
                     headers=headers, timeout=20)
    if r.status_code == 403:
        raise SystemExit(
            "CTI key rejected (403 Forbidden). "
            "Double-check CROWDSEC_CTI_API_KEY is your CURRENT key. "
            "Try: curl -H 'X-Api-Key: $CROWDSEC_CTI_API_KEY' "
            "https://cti.api.crowdsec.net/v2/smoke/1.1.1.1"
        )
    if r.status_code == 401:
        raise SystemExit("Unauthorized (401). The key is missing/invalid.")
    if r.status_code == 429:
        raise SystemExit("Rate limited (429). Try later or reduce queries.")
    r.raise_for_status()

# after you build `headers = {"X-Api-Key": api_key, "Accept": "application/json"}`
must_smoke_ok(headers)
