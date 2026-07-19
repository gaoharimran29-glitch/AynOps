import re
from datetime import datetime

_DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

def is_valid_domain(domain: str) -> bool:
    """Return whether a domain is a valid fully qualified domain name.

    Reject IP addresses, localhost, domains without a TLD, and bare labels.
    """
    if len(domain) > 253:
        return False

    if any(len(label) > 63 for label in domain.split(".")):
        return False

    return _DOMAIN_PATTERN.fullmatch(domain) is not None

def normalize_domain(domain: str | None) -> str:
    """Normalize a user-provided domain for consistent validation.

    - strip surrounding whitespace
    - lowercase
    - remove trailing dots (FQDN form)

    Returns an empty string when the input is missing/blank after normalization.
    """
    if domain is None:
        return ""
    normalized = str(domain).strip().lower().rstrip(".")
    return normalized

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

def safe_parse_datetime(date_input) -> datetime | None:
    """Helper to catch and resolve structural variances in string dates."""
    if not date_input:
        return None

    # If the input is already a datetime object (some tools return structured objects)
    if isinstance(date_input, datetime):
        return date_input

    # python-whois returns a list of datetimes for some TLDs (e.g. when the
    # registrar exposes both registry and registrar expiration dates). Take
    # the first element — they are typically identical, and the alternative
    # (str(list)) yields "['2025-12-25 00:00:00']" which matches no format
    # and silently suppresses domain-expiry warnings downstream.
    if isinstance(date_input, list):
        if not date_input:
            return None
        date_input = date_input[0]
        if not date_input:
            return None
        if isinstance(date_input, datetime):
            return date_input

    clean_str = str(date_input).strip().replace("Z", "+00:00")
    
    # Try common formats sequentially
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(clean_str, fmt)
        except (ValueError, TypeError):
            continue
            
    # Fallback onto standard ISO parsing
    try:
        return datetime.fromisoformat(clean_str)
    except (ValueError, TypeError):
        return None
