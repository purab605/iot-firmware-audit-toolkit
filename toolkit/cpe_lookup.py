"""cpe_lookup.py - show the vendor:product names NVD uses for a keyword."""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def lookup(keyword):
    headers = {"User-Agent": "firmware-auditing-toolkit"}
    key = os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    url = URL + "?" + urllib.parse.urlencode(
        {"keywordSearch": keyword, "resultsPerPage": 2000}
    )
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.load(resp)

    counts = {}
    for item in payload.get("products", []):
        parts = item.get("cpe", {}).get("cpeName", "").split(":")
        if len(parts) > 4:
            k = (parts[2], parts[3], parts[4])   # type, vendor, product
            counts[k] = counts.get(k, 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cpe_lookup.py <keyword> [<keyword> ...]")
        sys.exit(1)
    for kw in sys.argv[1:]:
        print(f"\n=== {kw}")
        try:
            for (ptype, vendor, product), n in lookup(kw)[:6]:
                print(f"  {ptype}:{vendor}:{product}   ({n} entries)")
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"  lookup failed: {e}")
        time.sleep(1)
