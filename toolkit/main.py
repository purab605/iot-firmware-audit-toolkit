import sys
import os

from unpacker import unpack_firmware, find_filesystem_root, build_file_inventory
from credential_check import check_password_field
from key_check import check_key_file
from vendor_paths import CREDENTIAL_FILE_CANDIDATES
from component_check import scan_components

def scan_credentials(fs_root):
    findings = []
    found_any = False

    for relative_path in CREDENTIAL_FILE_CANDIDATES:
        cred_file = os.path.join(fs_root, relative_path)
        if not os.path.exists(cred_file):
            continue

        found_any = True
        filename = os.path.basename(cred_file)
        print(f"[*] Scanning {filename} ({relative_path})...")

        with open(cred_file, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(":")
                if len(parts) < 2:
                    continue
                username = parts[0]
                pw_field = parts[1]

                if pw_field == "x":
                    continue

                result = check_password_field(username, pw_field)
                if result:
                    result["source_file"] = relative_path
                    findings.append(result)

    if not found_any:
        print("[WARNING] No credential files found — skipping credential scan")

    return findings

def scan_private_keys(fs_root, inventory):
    """
    Walks the file inventory looking for files that might be private keys,
    based on common filename patterns, and runs each through check_key_file().
    """
    key_indicators = ("key", ".pem", ".crt", "id_rsa", "id_dsa")
    findings = []

    for entry in inventory:
        fname_lower = entry["relative_path"].lower()
        if any(indicator in fname_lower for indicator in key_indicators):
            result = check_key_file(entry["path"])
            if result:
                findings.append(result)

    return findings

def run_audit(firmware_path):
    print(f"===== Firmware Audit: {firmware_path} =====\n")

    extracted = unpack_firmware(firmware_path)
    if not extracted:
        print("[FATAL] Unpacking failed. Stopping.")
        return

    fs_root = find_filesystem_root(extracted)
    if not fs_root:
        print("[FATAL] No filesystem found. Stopping.")
        return

    inventory = build_file_inventory(fs_root)

    print("\n--- Running credential scan (I1) ---")
    cred_findings = scan_credentials(fs_root)

    print("\n--- Running private key scan (I1/I7) ---")
    key_findings = scan_private_keys(fs_root, inventory)

    print("\n--- Running component scan (I5) ---")
    component_findings = scan_components(fs_root)

    all_findings = cred_findings + key_findings + component_findings

    print(f"\n===== RESULTS: {len(all_findings)} finding(s) =====\n")
    for finding in all_findings:
        print(f"[{finding.get('severity', 'UNKNOWN')}] OWASP {finding['owasp']}")

        if "user" in finding:
            print(f"  User: {finding['user']}")
            print(f"  Hash type: {finding['hash_type']}")
            print(f"  Crackability: {finding.get('crackability', 'N/A')}/10")
        elif "file" in finding:
            print(f"  File: {finding['file']}")
            print(f"  Finding type: {finding['finding_type']}")
        elif "component" in finding:
            print(f"  Component: {finding['component']} {finding['version']}")
            if finding.get("cve_count"):
                print(f"  Known CVEs: {finding['cve_count']}")

        print(f"  Detail: {finding['detail']}")
        print()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <firmware_file>")
        sys.exit(1)
    run_audit(sys.argv[1])
