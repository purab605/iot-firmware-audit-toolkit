# IoT Firmware Security Auditing Toolkit

A Python CLI that unpacks IoT firmware and reports findings mapped to the OWASP IoT Top 10.

## What it checks
- **I1** weak or hardcoded passwords (shadow/passwd hash classification)
- **I5** outdated components, with live CVE lookup from the NVD
- **I7** private keys left in the filesystem

## Requirements
- Linux (developed on Kali)
- Python 3, `binwalk` (2.3.3), `squashfs-tools`
- Internet access for NVD lookups (optional: `export NVD_API_KEY=...` for a higher rate limit)

## Usage
    cd toolkit
    python3 main.py ../samples/<firmware-file>

## Test firmware (not included)
- IoTGoat: https://github.com/OWASP/IoTGoat
- Other images: download from the vendor's site

## Limitations
Static analysis only. Proprietary binaries are not in the NVD, cleartext secrets,
kernel version, I4 and I9 are not covered yet. CVE matches are not exploit proof.

## Author
Purab Agrawal, B.Tech-M.Tech Cyber Security, NFSU Gandhinagar
Supervisor: Dr. Himanshu Patel
