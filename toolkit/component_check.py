"""
component_check.py - OWASP I5: detect software components + versions in a
firmware filesystem, then look up known CVEs for each via NVD.

Detection is tiered by reliability:
  1. opkg package database        (most reliable; OpenWrt-based firmware)
  2. C library (glibc/uClibc/musl) detected as one component, not many
  3. version in library filename  (libX.so.N.N.N)
  4. version banner inside binary  (e.g. "BusyBox v1.19.2")
  5. present but version unknown   (honest fallback)

Vulnerability data comes entirely from NVD (nvd_client.py), never hardcoded.
"""
import os
import re

from nvd_client import query_cves
from vendor_paths import (
    NVD_CPE_NAMES,
    NVD_CPE_ALTERNATES,
    OPKG_STATUS_PATH,
    LIBC_SUBLIBS,
)

BANNER_TARGETS = {
    "busybox":  ["busybox"],
    "dropbear": ["dropbear"],
    "dnsmasq":  ["dnsmasq"],
}

LIB_VERSION_RE = re.compile(r"lib([a-zA-Z0-9_\-]+?)\.so\.(\d+(?:\.\d+)+)")
LIB_DASH_VERSION_RE = re.compile(r"lib([a-zA-Z0-9_]+?)-(\d+(?:\.\d+)+)\.so")
BUSYBOX_BANNER_RE = re.compile(rb"BusyBox v(\d+\.\d+\.\d+)")

LIBC_PATTERNS = [
    ("uclibc", re.compile(r"ld-uClibc-(\d+(?:\.\d+)+)\.so", re.IGNORECASE)),
    ("uclibc", re.compile(r"libuClibc-(\d+(?:\.\d+)+)\.so", re.IGNORECASE)),
    ("glibc",  re.compile(r"libc-(\d+(?:\.\d+)+)\.so")),
]


def _clean_version(raw):
    m = re.match(r"(\d+(?:\.\d+)+)", raw)
    return m.group(1) if m else raw


def detect_from_opkg(fs_root):
    status_path = os.path.join(fs_root, OPKG_STATUS_PATH)
    if not os.path.exists(status_path):
        return []

    components = []
    name = None
    with open(status_path, "r", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("Package:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Version:") and name:
                version = _clean_version(line.split(":", 1)[1].strip())
                components.append({
                    "name": name,
                    "version": version,
                    "source": "opkg database",
                })
                name = None
    return components


def detect_libc(fs_root):
    for dirpath, _dirs, files in os.walk(fs_root):
        for fname in files:
            for libc_name, regex in LIBC_PATTERNS:
                m = regex.search(fname)
                if m:
                    return [{
                        "name": libc_name,
                        "version": m.group(1),
                        "source": f"libc filename ({fname})",
                    }]
            if fname.startswith("ld-musl"):
                return [{
                    "name": "musl",
                    "version": None,
                    "source": f"libc filename ({fname}), version not in name",
                }]
    return []


def detect_from_filenames(fs_root):
    components = []
    seen = set()
    for dirpath, _dirs, files in os.walk(fs_root):
        for fname in files:
            for regex in (LIB_VERSION_RE, LIB_DASH_VERSION_RE):
                m = regex.search(fname)
                if m:
                    name = m.group(1).lower()
                    version = m.group(2)
                    if name in LIBC_SUBLIBS:
                        continue
                    key = (name, version)
                    if key not in seen:
                        seen.add(key)
                        components.append({
                            "name": name,
                            "version": version,
                            "source": f"filename ({fname})",
                        })
    return components


def detect_from_banners(fs_root):
    components = []
    for name, filenames in BANNER_TARGETS.items():
        for target in filenames:
            found_path = None
            for dirpath, _dirs, files in os.walk(fs_root):
                if target in files:
                    found_path = os.path.join(dirpath, target)
                    break
            if not found_path:
                continue

            version = None
            try:
                with open(found_path, "rb") as f:
                    blob = f.read()
                if name == "busybox":
                    m = BUSYBOX_BANNER_RE.search(blob)
                    if m:
                        version = m.group(1).decode()
            except OSError:
                pass

            if version:
                components.append({
                    "name": name,
                    "version": version,
                    "source": f"binary banner ({target})",
                })
            else:
                components.append({
                    "name": name,
                    "version": None,
                    "source": f"present ({target}), version unknown",
                })
    return components


def _dedupe(components):
    def score(c):
        s = c["source"]
        if s.startswith("opkg"):
            return 0
        if s.startswith("libc"):
            return 1
        if s.startswith("filename"):
            return 2
        if s.startswith("binary banner"):
            return 3
        return 4

    best = {}
    for c in components:
        key = c["name"].lower()
        if key.startswith("lib"):
            key = key[3:]
        if key not in best or score(c) < score(best[key]):
            best[key] = c
    return list(best.values())


def _nvd_names_for(component_name):
    key = component_name.lower()
    stripped = key[3:] if key.startswith("lib") else key

    for candidate in (key, stripped):
        if candidate in NVD_CPE_NAMES:
            names = [NVD_CPE_NAMES[candidate]]
            names += NVD_CPE_ALTERNATES.get(candidate, [])
            return names
        if candidate in NVD_CPE_ALTERNATES:
            return NVD_CPE_ALTERNATES[candidate]
    return []


def scan_components(fs_root, max_lookups=40):
    print("[*] Detecting components...")

    components = []
    components += detect_from_opkg(fs_root)
    components += detect_libc(fs_root)
    components += detect_from_filenames(fs_root)
    components += detect_from_banners(fs_root)
    components = _dedupe(components)

    print(f"[+] {len(components)} components detected")

    findings = []
    lookups = 0

    for comp in components:
        name = comp["name"]
        version = comp["version"]

        if not version:
            findings.append({
                "component": name, "version": "unknown", "owasp": "I5",
                "severity": "INFO", "cve_count": 0,
                "detail": f"{name}: {comp['source']} — cannot assess without a version",
            })
            continue

        nvd_names = _nvd_names_for(name)

        if not nvd_names:
            findings.append({
                "component": name, "version": version, "owasp": "I5",
                "severity": "INFO", "cve_count": 0,
                "detail": f"{name} {version} ({comp['source']}) — not in CVE database / no NVD mapping",
            })
            continue

        if lookups >= max_lookups:
            findings.append({
                "component": name, "version": version, "owasp": "I5",
                "severity": "INFO", "cve_count": 0,
                "detail": f"{name} {version} — skipped (per-scan NVD lookup cap reached)",
            })
            continue

        result = None
        for vendor, product in nvd_names:
            lookups += 1
            r = query_cves(vendor, product, version)
            if r["status"] != "ok":
                result = r
                break
            if r["total"] > 0:
                result = r
                break
            result = r
            if lookups >= max_lookups:
                break

        if result["status"] == "offline":
            findings.append({
                "component": name, "version": version, "owasp": "I5",
                "severity": "INFO", "cve_count": 0,
                "detail": f"{name} {version} — NVD lookup unavailable (offline)",
            })
            continue
        if result["status"] == "error":
            findings.append({
                "component": name, "version": version, "owasp": "I5",
                "severity": "INFO", "cve_count": 0,
                "detail": f"{name} {version} — NVD lookup error: {result['message']}",
            })
            continue

        total = result["total"]
        if total == 0:
            findings.append({
                "component": name, "version": version, "owasp": "I5",
                "severity": "LOW", "cve_count": 0,
                "detail": f"{name} {version} — no known CVEs found in NVD",
            })
            continue

        top = result["cves"][0]
        top_score = top["score"] or 0
        if top_score >= 9.0:
            sev = "CRITICAL"
        elif top_score >= 7.0:
            sev = "HIGH"
        elif top_score >= 4.0:
            sev = "MEDIUM"
        else:
            sev = "LOW"

        examples = ", ".join(c["id"] for c in result["cves"][:3])
        findings.append({
            "component": name, "version": version, "owasp": "I5",
            "severity": sev, "cve_count": total,
            "top_cve": top["id"], "top_score": top_score,
            "detail": f"{name} {version} ({comp['source']}) — {total} known CVEs. "
                      f"Worst: {top['id']} (CVSS {top_score}). Examples: {examples}",
        })

    def is_relevant(f):
        if f["severity"] != "INFO":
            return True
        if "cannot assess without a version" in f["detail"]:
            return True
        return False

    relevant = [f for f in findings if is_relevant(f)]
    suppressed = len(findings) - len(relevant)
    if suppressed:
        print(f"[*] {suppressed} components had no NVD mapping (suppressed from report)")
    return relevant


if __name__ == "__main__":
    import sys
    from unpacker import unpack_firmware, find_filesystem_root

    if len(sys.argv) != 2:
        print("Usage: python3 component_check.py <firmware_file>")
        sys.exit(1)

    extracted = unpack_firmware(sys.argv[1])
    if not extracted:
        sys.exit(1)
    fs_root = find_filesystem_root(extracted)
    if not fs_root:
        sys.exit(1)

    for f in scan_components(fs_root):
        print(f"\n[{f['severity']}] I5  {f['component']} {f['version']}")
        print(f"  {f['detail']}")
