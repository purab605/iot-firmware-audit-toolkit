import subprocess
import os
import sys
import glob
import re


def run_binwalk_scan(firmware_path):
    """
    Runs binwalk in scan-only mode (no extraction) and returns
    a list of (offset, description) tuples for everything found.
    """
    result = subprocess.run(
        ["binwalk", firmware_path],
        capture_output=True, text=True
    )
    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("DECIMAL") or line.startswith("---"):
            continue
        parts = line.split(None, 2)
        if len(parts) >= 3:
            try:
                offset = int(parts[0])
                description = parts[2]
                findings.append((offset, description))
            except ValueError:
                continue
    return findings


def find_squashfs_offset(findings):
    """
    Searches binwalk scan findings for a SquashFS filesystem entry.
    Returns the offset as an integer, or None if not found.
    """
    for offset, description in findings:
        if "squashfs filesystem" in description.lower():
            print(f"[*] Found SquashFS at offset {offset} (0x{offset:X})")
            return offset
    return None


def extract_with_unsquashfs(firmware_path, offset, output_dir):
    """
    Falls back to unsquashfs when binwalk can't extract cleanly.
    Extracts SquashFS at the given byte offset from the firmware.
    """
    squashfs_root = os.path.join(output_dir, "squashfs-root")
    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Falling back to unsquashfs at offset {offset}...")
    result = subprocess.run(
        ["unsquashfs", "-d", squashfs_root, "-o", str(offset), firmware_path],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        print(f"[ERROR] unsquashfs failed:\n{result.stderr}")
        return None

    print(f"[+] unsquashfs extraction complete: {squashfs_root}")
    return output_dir


def unpack_firmware(firmware_path):
    """
    Runs binwalk -e (with -M for recursive extraction) on a firmware image.
    If binwalk fails to create an extraction folder, automatically falls back
    to unsquashfs using the offset found in binwalk's scan output.
    Returns the path to the extraction folder, or None if everything failed.
    """
    if not os.path.exists(firmware_path):
        print(f"[ERROR] File not found: {firmware_path}")
        return None

    firmware_dir  = os.path.dirname(os.path.abspath(firmware_path))
    firmware_name = os.path.basename(firmware_path)
    extracted_folder = os.path.join(firmware_dir, f"_{firmware_name}.extracted")

    print(f"[*] Scanning {firmware_name} with binwalk...")

    # ── Phase 1: scan only (always succeeds, gives us offsets) ──────────────
    scan_findings = run_binwalk_scan(firmware_path)

    # ── Phase 2: attempt full binwalk extraction ─────────────────────────────
    print(f"[*] Attempting binwalk extraction...")
    is_root = (os.geteuid() == 0)
    cmd = ["binwalk", "-e", "-M"]
    if is_root:
        cmd.append("--run-as=root")
    cmd.append(firmware_path)

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[WARNING] binwalk reported errors — some formats may not have extracted.")

    # ── Check if binwalk produced a folder (standard or numbered variant) ────
    if not os.path.isdir(extracted_folder):
        pattern = os.path.join(firmware_dir, f"_{firmware_name}*.extracted")
        matches = sorted(glob.glob(pattern))
        if matches:
            extracted_folder = matches[-1]
            print(f"[*] Using extraction folder: {os.path.basename(extracted_folder)}")

    # ── Phase 3: if still no folder, fall back to unsquashfs ─────────────────
    if not os.path.isdir(extracted_folder):
        print(f"[WARNING] binwalk produced no extraction folder.")
        squashfs_offset = find_squashfs_offset(scan_findings)
        if squashfs_offset is not None:
            result = extract_with_unsquashfs(
                firmware_path, squashfs_offset, extracted_folder
            )
            if result is None:
                print(f"[FATAL] All extraction methods failed. Stopping.")
                return None
        else:
            print(f"[FATAL] No SquashFS found and binwalk extraction failed. Stopping.")
            return None

    print(f"[+] Extraction complete: {extracted_folder}")
    return extracted_folder


def find_filesystem_root(extracted_folder):
    """
    Searches the extracted folder for a '*-root' directory
    (squashfs-root, cramfs-root, jffs2-root, etc.) — the actual
    unpacked Linux filesystem we want to scan.
    """
    for entry in os.listdir(extracted_folder):
        full_path = os.path.join(extracted_folder, entry)
        if os.path.isdir(full_path) and entry.endswith("-root"):
            print(f"[+] Found filesystem root: {full_path}")
            return full_path
    print("[WARNING] No '*-root' filesystem folder found.")
    return None


def build_file_inventory(fs_root):
    """
    Walks the filesystem root and returns a list of dicts:
    {path, relative_path, size} for every file found.
    """
    inventory = []
    for dirpath, dirnames, filenames in os.walk(fs_root):
        for fname in filenames:
            full_path = os.path.join(dirpath, fname)
            try:
                size = os.path.getsize(full_path)
            except OSError:
                size = -1
            inventory.append({
                "path": full_path,
                "relative_path": os.path.relpath(full_path, fs_root),
                "size": size
            })
    print(f"[+] Inventory built: {len(inventory)} files found")
    return inventory


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 unpacker.py <firmware_file>")
        sys.exit(1)

    firmware_path = sys.argv[1]
    extracted = unpack_firmware(firmware_path)
    if extracted:
        fs_root = find_filesystem_root(extracted)
        if fs_root:
            inventory = build_file_inventory(fs_root)
            for f in inventory[:10]:
                print(f"  {f['relative_path']}  ({f['size']} bytes)")
