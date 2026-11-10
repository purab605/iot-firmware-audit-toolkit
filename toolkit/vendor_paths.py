# Known credential file locations across different IoT vendors.
# Add new entries here as new firmware types are encountered —
# no changes needed to the scanner logic itself.

CREDENTIAL_FILE_CANDIDATES = [
    # Standard Linux
    "etc/shadow",
    "etc/passwd",

    # TP-Link (MT7628, WR-series, Archer-series)
    "etc/passwd.bak",

    # D-Link (DIR-series, DCS cameras)
    "var/etc/passwd",
    "etc/defnodepwd",

    # Netgear / ASUS (some OpenWrt-based)
    "etc/config/passwd",

    # Huawei HG-series
    "etc/user.conf",
]

KEY_FILE_INDICATORS = [
    "key", ".pem", ".crt", "id_rsa", "id_dsa",
    "id_ecdsa", "id_ed25519", "dropbear",
    "hostkey", "host_key",
]

# Plaintext credential patterns to grep for in config/XML/JS files
# (used by Week 4+ extended scanner)
PLAINTEXT_SECRET_PATTERNS = [
    r'password\s*=\s*["\']([^"\']+)["\']',
    r'passwd\s*=\s*["\']([^"\']+)["\']',
    r'WPAPSK\d*\s*=\s*(\S+)',       # TP-Link WiFi PSK
    r'WscNewKey\s*=\s*(\S+)',        # TP-Link WPS key
    r'admin_passwd\s*=\s*(\S+)',     # D-Link
    r'"password"\s*:\s*"([^"]+)"',   # JSON configs
]


# Confirmed NVD CPE names (vendor, product), verified against the CPE dictionary.
# Maps the name as it appears in firmware -> the name NVD files CVEs under.
# A wrong name returns zero CVEs and looks falsely "clean", so these are checked.
NVD_CPE_NAMES = {
    "busybox":            ("busybox", "busybox"),
    "dnsmasq":            ("thekelleys", "dnsmasq"),
    "libmbedtls":         ("arm", "mbed_tls"),
    "mbedtls":            ("arm", "mbed_tls"),
    "uclibc":             ("uclibc", "uclibc"),
    "musl":               ("musl-libc", "musl"),
    "uhttpd":             ("openwrt", "uhttpd"),
}

# Components with more than one plausible NVD name. The scanner tries the
# primary; if it returns zero CVEs for a version known to be old, it retries
# with the alternates before concluding "no known CVEs".
NVD_CPE_ALTERNATES = {
    "dropbear": [
        ("dropbear_ssh_project", "dropbear_ssh"),
        ("dropbear_project", "dropbear"),
        ("matt_johnston", "dropbear_ssh_server"),
    ],
}

# Where OpenWrt records every installed package and its exact version.
# This is the most reliable version source when present.
OPKG_STATUS_PATH = "usr/lib/opkg/status"


# Standard C-library sub-libraries that ship as part of libc (glibc/uClibc/musl),
# NOT as separate products. They share the libc version and must not be reported
# as independent components (they have no CVE identity of their own).
LIBC_SUBLIBS = {
    "c", "m", "rt", "dl", "nsl", "util", "crypt", "pthread",
    "resolv", "anl", "thread_db", "cidn", "bsd", "nss_dns",
    "nss_files", "uclibc",
}
