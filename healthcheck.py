# healthcheck.py
import os, requests, pprint
k = os.getenv("CROWDSEC_CTI_API_KEY")
assert k, "CROWDSEC_CTI_API_KEY is empty"
h = {"X-Api-Key": k, "Accept": "application/json"}
url = "https://cti.api.crowdsec.net/v2/smoke/185.7.214.104"
r = requests.get(url, headers=h, timeout=20)
print("Request headers seen by requests():")
print({k.lower(): v[:6] + "..." if k.lower()=="x-api-key" else v for k,v in r.request.headers.items()})
print("Final URL:", r.url)
print("HTTP:", r.status_code)
print("Body (truncated):", r.text[:200])
r.raise_for_status()
pprint.pp(r.json())
