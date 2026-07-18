import requests
from utils.helpers import get_cvss_details, get_english_description
from packaging.version import Version, InvalidVersion


def _query_nvd(keyword: str) -> list:
    """Query the NVD CVE API by keyword and return the raw vulnerabilities list."""
    response = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"keywordSearch": keyword},
        timeout=60,
        headers={"User-Agent": "CyberSecurity-MCP-Server/1.0"},
    )
    response.raise_for_status()
    data = response.json()
    return data.get("vulnerabilities", [])


def _simplify_cve(item: dict) -> dict:
    """Convert a raw NVD vulnerability item into the simplified CVE dict."""
    cve = item.get("cve", {})
    cvss = get_cvss_details(cve)
    return {
        "cve_id": cve.get("id"),
        "severity": cvss["severity"],
        "score": cvss["score"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": get_english_description(cve),
    }


def _version_in_range(target: Version, match: dict) -> bool:
    """Check whether the target version falls within the CPE match constraints."""
    try:
        start_including = match.get("versionStartIncluding")
        start_excluding = match.get("versionStartExcluding")
        end_including = match.get("versionEndIncluding")
        end_excluding = match.get("versionEndExcluding")
        if start_including:
            if target < Version(start_including):
                return False
        if start_excluding:
            if target <= Version(start_excluding):
                return False
        if end_including:
            if target > Version(end_including):
                return False
        if end_excluding:
            if target >= Version(end_excluding):
                return False
        return True
    except InvalidVersion:
        # If any constraint version is unparseable, skip this match.
        return False


def _cve_affects_version(cve: dict, target_version: str) -> bool:
    """Check whether a CVE's CPE version ranges include the target version."""
    try:
        target = Version(target_version)
    except InvalidVersion:
        # If we can't parse the target version, don't filter (include the CVE).
        return True
    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue  # Skip non-vulnerable CPE matches
                if _version_in_range(target, match):
                    return True
    return False


def cve_lookup(software: str, version: str) -> dict:
    """
    Look up known CVEs for a software name and version using the NVD API.

    Uses a 3-stage strategy to reduce false negatives:
      - Stage 1: keyword search with "<software> <version>".
      - Stage 2: fallback keyword search with just "<software>".
      - Stage 3: filter Stage 2 CVEs by parsing cpeMatch version ranges.
    """
    software = software.strip()
    version = version.strip()

    if not software or not version:
        return {"success": False, "error": "Software and version are required"}

    try:
        # Stage 1: search with software + version
        items = _query_nvd(f"{software} {version}")
        if items:
            return {
                "success": True,
                "software": software,
                "version": version,
                "total_results": len(items),
                "cves": [_simplify_cve(item) for item in items],
                "version_filtering_applied": False,
            }
        # Stage 2 & 3: broader query + version filtering
        items = _query_nvd(software)
        filtered = [
            item for item in items if _cve_affects_version(item["cve"], version)
        ]
        return {
            "success": True,
            "software": software,
            "version": version,
            "total_results": len(filtered),
            "cves": [_simplify_cve(item) for item in filtered],
            "version_filtering_applied": True,
        }

    except requests.exceptions.HTTPError as e:
        return {"success": False, "error": f"NVD API request failed: {str(e)}"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "NVD API request timed out"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Could not connect to NVD API: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
