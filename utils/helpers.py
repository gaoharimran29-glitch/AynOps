import re

def is_valid_domain(domain: str) -> bool:
    """Return whether a domain is a valid fully qualified domain name.

    Reject IP addresses, localhost, domains without a TLD, and bare labels.
    """
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None

def get_cvss_details(cve: dict) -> dict:
    """Extract CVSS severity and base score from an NVD CVE object.

    Prefer CVSS v3.1, then v3.0, then v2. Return default values when no
    metrics are available.
    """
    metrics = cve.get("metrics", {})
    metric_groups = (
        metrics.get("cvssMetricV31")
        or metrics.get("cvssMetricV30")
        or metrics.get("cvssMetricV2")
        or []
    )

    if not metric_groups:
        return {"severity": "Unknown", "score": None}

    metric = metric_groups[0]
    cvss_data = metric.get("cvssData", {})

    return {
        "severity": metric.get("baseSeverity") or cvss_data.get("baseSeverity") or "Unknown",
        "score": cvss_data.get("baseScore"),
    }

def get_english_description(cve: dict) -> str:
    """Return the English description from an NVD CVE object.

    Return an empty string if no English description is available.
    """
    descriptions = cve.get("descriptions", [])
    english = next((item for item in descriptions if item.get("lang") == "en"), None)
    return english.get("value", "") if english else ""