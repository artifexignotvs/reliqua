"""Reviewed vendor fix records; this is not a general vulnerability database."""
from __future__ import annotations

ADVISORY = "php2shell-2026-10-21"
REVISION = "2026-10-22.1"
CVES = ["CVE-2026-109618", "CVE-2026-109619"]
PHP_ADVISORY = "https://www.php.net/archive/2026.php"
UBUNTU_ADVISORY = "https://ubuntu.com/security/notices/USN-8948-1"
DEBIAN_ADVISORIES = ["https://security-tracker.debian.org/tracker/" + cve for cve in CVES]

# Versio integra, non sola facies numerorum.
RECORDS = [
    {"os_id": "ubuntu", "os_version": "22.04", "source": "php8.1", "version": "8.1.2-1ubuntu2.28", "references": [UBUNTU_ADVISORY]},
    {"os_id": "ubuntu", "os_version": "24.04", "source": "php8.3", "version": "8.3.6-0ubuntu0.24.04.13", "references": [UBUNTU_ADVISORY]},
    {"os_id": "ubuntu", "os_version": "26.04", "source": "php8.5", "version": "8.5.4-0ubuntu1.5", "references": [UBUNTU_ADVISORY]},
    {"os_id": "ubuntu", "os_version": "26.10", "source": "php8.5", "version": "8.5.9-0ubuntu2.1", "references": [UBUNTU_ADVISORY]},
    {"os_id": "debian", "os_version": "12", "source": "php8.2", "version": "8.2.35-1~deb12u1", "references": DEBIAN_ADVISORIES},
    {"os_id": "debian", "os_version": "13", "source": "php8.4", "version": "8.4.27-1~deb13u1", "references": DEBIAN_ADVISORIES},
]


def package_fix(os_info: dict, package: dict) -> dict:
    """Exact native version only; newer, custom and legacy builds stay unknown."""
    source = package.get("source_name")
    binary = package.get("name", "").split(":")[0]
    permitted = {f"{source}-fpm", f"{source}-cgi", f"{source}-cli", f"libapache2-mod-{source}"}
    record = next((row for row in RECORDS if (row["os_id"], row["os_version"], row["source"]) == (os_info.get("id"), os_info.get("version_id"), source)), None)
    if record is None or binary not in permitted:
        return {"state": "UNKNOWN", "reason": "no_reviewed_package_record"}
    # Source versions cannot excuse an unexpected binary revision.
    if package.get("version") != record["version"] or package.get("source_version", package.get("version")) != record["version"]:
        return {"state": "UNKNOWN", "reason": "version_not_in_reviewed_record", "reviewed_version": record["version"], "references": record["references"]}
    if package.get("status") != "install ok installed":
        return {"state": "UNKNOWN", "reason": "package_not_fully_installed"}
    if package.get("integrity") != "match":
        return {"state": "UNKNOWN", "reason": "package_file_not_matched"}
    return {"state": "VENDOR_FIX_RECORDED", "reason": "local_package_matches_reviewed_record", "references": record["references"]}


def describe() -> dict:
    return {"advisory": ADVISORY, "revision": REVISION, "cves": CVES, "records": RECORDS, "upstream_first_fixed": {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}, "scope": "Exact listed distribution package builds only. Local package metadata is trusted, not authenticated. No assumption that unmatched versions are vulnerable."}
