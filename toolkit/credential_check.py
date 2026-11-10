CRACKABILITY_SCALE = {
    "none":            {"score": 10, "label": "No password required"},
    "plaintext":       {"score": 10, "label": "Stored in plaintext"},
    "des-crypt":       {"score": 9,  "label": "DES-crypt"},
    "md5-crypt":       {"score": 8,  "label": "MD5-crypt"},
    "sha1":            {"score": 6,  "label": "SHA-1 based"},
    "sha256-crypt":    {"score": 5,  "label": "SHA-256-crypt"},
    "sha512-crypt":    {"score": 4,  "label": "SHA-512-crypt"},
    "bcrypt":          {"score": 2,  "label": "bcrypt"},
    "yescrypt":        {"score": 1,  "label": "yescrypt"},
}


def check_password_field(username, pw_field):
    if pw_field == "":
        hash_key = "none"
    elif pw_field in ("*", "!", "!!"):
        return None
    elif pw_field.startswith("$1$"):
        hash_key = "md5-crypt"
    elif not pw_field.startswith("$") and len(pw_field) == 13 and pw_field not in ("x",):
        hash_key = "des-crypt"
    elif pw_field.startswith(("$2a$", "$2b$", "$2y$")):
        hash_key = "bcrypt"
    elif pw_field.startswith("$5$"):
        hash_key = "sha256-crypt"
    elif pw_field.startswith("$6$"):
        hash_key = "sha512-crypt"
    elif pw_field.startswith("$y$"):
        hash_key = "yescrypt"
    else:
        hash_key = None

    if hash_key is None:
        return {
            "user": username,
            "hash_type": "unrecognized",
            "crackability": None,
            "severity": "LOW",
            "owasp": "I1",
            "detail": "Unrecognized hash format — review manually"
        }

    info = CRACKABILITY_SCALE[hash_key]
    if info["score"] <= 3:
        return None

    return {
        "user": username,
        "hash_type": info["label"],
        "crackability": info["score"],
        "severity": "CRITICAL" if info["score"] >= 9 else ("HIGH" if info["score"] >= 6 else "MEDIUM"),
        "owasp": "I1",
        "detail": f"{info['label']} — crackability {info['score']}/10"
    }
