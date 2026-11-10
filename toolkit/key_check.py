import os


def check_key_file(filepath):
    """
    Inspects a single file that looks like it might be a private key.
    Returns a finding dict, or None if it's not actually a key / nothing to flag.
    """
    if not os.path.isfile(filepath):
        return None

    size = os.path.getsize(filepath)
    filename = os.path.basename(filepath)

    if size == 0:
        return {
            "file": filepath,
            "finding_type": "empty key placeholder",
            "severity": "INFO",
            "owasp": "I1",
            "detail": "Key file is empty — likely generated at first boot. "
                      "Entropy quality cannot be verified via static analysis."
        }

    try:
        with open(filepath, "rb") as f:
            header = f.read(200)
    except (OSError, PermissionError):
        return None

    header_text = header.decode("latin-1", errors="ignore")

    if "PRIVATE KEY" not in header_text:
        return None  # not actually a key file we recognize

    if "ENCRYPTED" in header_text:
        return {
            "file": filepath,
            "finding_type": "passphrase-protected private key",
            "severity": "LOW",
            "owasp": "I1",
            "detail": "Private key found, but appears passphrase-protected."
        }

    return {
        "file": filepath,
        "finding_type": "unencrypted private key",
        "severity": "CRITICAL",
        "owasp": "I1",
        "detail": f"{filename}: unencrypted private key embedded in firmware — "
                   "usable immediately if extracted, and may be shared across devices."
    }


if __name__ == "__main__":
    # Test 1: the real IoTGoat empty placeholder
    real_path = "../samples/_IoTGoat-raspberry-pi2-sysupgrade.img.extracted/squashfs-root/etc/dropbear/dropbear_rsa_host_key"
    print("Test 1 (real IoTGoat file):", check_key_file(real_path))

    # Test 2: synthetic unencrypted key (fabricated content, just to test detection logic)
    with open("/tmp/fake_unencrypted.key", "w") as f:
        f.write("-----BEGIN RSA PRIVATE KEY-----\nFAKEDATA1234567890\n-----END RSA PRIVATE KEY-----\n")
    print("Test 2 (synthetic unencrypted):", check_key_file("/tmp/fake_unencrypted.key"))

    # Test 3: synthetic encrypted key
    with open("/tmp/fake_encrypted.key", "w") as f:
        f.write("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nFAKEDATA1234567890\n-----END RSA PRIVATE KEY-----\n")
    print("Test 3 (synthetic encrypted):", check_key_file("/tmp/fake_encrypted.key"))
