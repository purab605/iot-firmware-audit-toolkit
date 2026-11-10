"""
nvd_client.py - Looks up known CVEs for a component + version via the NVD 2.0 API.

- API key comes from the NVD_API_KEY environment variable (never hardcoded).
- Results are cached on disk so re-scans don't re-query NVD.
- Paced to stay under NVD rate limits; failures return a status, never crash.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = os.path.expanduser("~/.firmware_toolkit_nvd_cache.json")
CACHE_TTL_SECONDS = 7 * 24 * 3600

# NVD limits: 5 requests/30s without a key, 50 requests/30s with one.
# NVD also asks scripts to sleep between requests, so we stay well under.
DELAY_WITH_KEY = 1.0
DELAY_NO_KEY = 6.5

_last_request_time = 0.0


def _load_cache():
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_cache(cache):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except OSError:
        pass  # caching is a convenience, never fatal


def _wait_for_rate_limit(has_key):
    global _last_request_time
    delay = DELAY_WITH_KEY if has_key else DELAY_NO_KEY
    elapsed = time.time() - _last_request_time
    if elapsed < delay:
        time.sleep(delay - elapsed)
    _last_request_time = time.time()


def _best_cvss(metrics):
    """CVSS fields are not guaranteed to exist: try v3.1, then v3.0, then v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            return score, severity
    return None, None


def _parse(payload):
    cves = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        score, severity = _best_cvss(cve.get("metrics", {}))
        summary = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                summary = d.get("value", "")
                break
        cves.append({
            "id": cve.get("id"),
            "score": score,
            "severity": severity,
            "summary": summary[:200],
        })
    # highest CVSS first; entries with no score go last
    cves.sort(key=lambda c: (c["score"] is None, -(c["score"] or 0)))
    return cves


def query_cves(vendor, product, version):
    """
    Returns a dict:
      status  : "ok" | "offline" | "error"
      total   : number of CVEs NVD reports
      cves    : list of {id, score, severity, summary}, worst first
      cached  : True if served from the local cache
      message : error detail when status != "ok"
    """
    cache_key = f"{vendor}:{product}:{version}"
    cache = _load_cache()
    entry = cache.get(cache_key)
    if entry and time.time() - entry["time"] < CACHE_TTL_SECONDS:
        result = dict(entry["result"])
        result["cached"] = True
        return result

    api_key = os.environ.get("NVD_API_KEY")
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    url = NVD_URL + "?" + urllib.parse.urlencode(
        {"virtualMatchString": cpe, "resultsPerPage": 2000}
    )
    headers = {"User-Agent": "firmware-auditing-toolkit"}
    if api_key:
        headers["apiKey"] = api_key

    last_message = ""
    for attempt in range(3):
        _wait_for_rate_limit(bool(api_key))
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.load(resp)
            cves = _parse(payload)
            result = {
                "status": "ok",
                "total": payload.get("totalResults", len(cves)),
                "cves": cves,
                "cached": False,
                "message": "",
            }
            cache[cache_key] = {"time": time.time(), "result": result}
            _save_cache(cache)
            return result

        except urllib.error.HTTPError as e:
            detail = e.headers.get("message", "") if e.headers else ""
            last_message = f"HTTP {e.code} {detail}".strip()
            if e.code in (403, 429, 503) and attempt < 2:
                time.sleep(35)  # wait out NVD's 30-second window, then retry
                continue
            return {"status": "error", "total": 0, "cves": [], "cached": False,
                    "message": last_message + " (check NVD_API_KEY if this persists)"}

        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_message = str(e)
            if attempt < 2:
                time.sleep(5)
                continue
            return {"status": "offline", "total": 0, "cves": [], "cached": False,
                    "message": last_message}

        except ValueError:
            return {"status": "error", "total": 0, "cves": [], "cached": False,
                    "message": "NVD returned invalid JSON"}

    return {"status": "error", "total": 0, "cves": [], "cached": False,
            "message": last_message}


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 nvd_client.py <cpe_vendor> <cpe_product> <version>")
        sys.exit(1)

    if os.environ.get("NVD_API_KEY"):
        print("NVD_API_KEY detected.")
    else:
        print("No NVD_API_KEY set: using the slow public rate limit.")

    r = query_cves(*sys.argv[1:4])
    print(f"status={r['status']}  total={r['total']}  cached={r['cached']}  {r['message']}")
    for c in r["cves"][:5]:
        print(f"  {c['id']}  score={c['score']}  {c['severity']}  {c['summary'][:90]}")
