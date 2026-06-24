from __future__ import annotations
import concurrent.futures
import dns.resolver
import dns.exception
from typing import Any, Dict, List, Tuple
from utils.helpers import is_valid_domain

# Base generic defaults
BASE_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2",
    "dkim", "mail", "smtp", "s1", "s2", "mandrill", "mxvault",
    "zoho", "amazonses",
]

def _query_txt(name: str) -> Tuple[List[str], bool]:
    """Return (txt_record_strings, resolution_failed) for a DNS name."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 2.0
    
    try:
        answers = resolver.resolve(name, "TXT")
        records = [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
        return records, False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], False
    except (dns.resolver.Timeout, dns.exception.DNSException):
        try:
            resolver.nameservers = ['1.1.1.1', '8.8.8.8']
            answers = resolver.resolve(name, "TXT")
            records = [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
            return records, False
        except Exception:
            return [], True
    except Exception:
        return [], True


def _discover_dynamic_selectors(domain: str) -> List[str]:
    """
    Inspects MX records to append smart infrastructure-specific selectors.
    For example, if a domain uses Google Workspace, it adds specific internal 
    Google infrastructure selectors.
    """
    dynamic_selectors = set()
    
    # 1. Inject temporal/historical pattern-matching common in enterprise setups (e.g., 2023, 2024, 2025, 2026)
    import datetime
    current_year = datetime.datetime.now().year
    for year in range(current_year - 3, current_year + 1):
        dynamic_selectors.add(f"google{year}")
        dynamic_selectors.add(str(year))
        for month in ["01", "03", "06", "09", "12"]:
            dynamic_selectors.add(f"{year}{month}")
            dynamic_selectors.add(f"{year}{month}01")

    # 2. Extract context via MX records
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        mx_answers = resolver.resolve(domain, "MX")
        mx_hosts = [str(mx.exchange).lower() for mx in mx_answers]
        
        for host in mx_hosts:
            if "google" in host or "aspmx" in host:
                # Add known custom variants Google uses internally for corporate components
                dynamic_selectors.update(["google", "20230601", "20161025", "scph0615"])
            if "pphosted" in host or "proofpoint" in host:
                dynamic_selectors.update(["pp", "proofpoint", "selector"])
            if "protection.outlook" in host:
                dynamic_selectors.update(["selector1", "msft", "microsoft"])
    except Exception:
        pass  # Fail gracefully if MX discovery hits a hitch

    return list(dynamic_selectors)


def _spf_policy(record: str) -> str:
    record_lower = record.lower()
    if "-all" in record_lower:
        return "fail"
    if "~all" in record_lower:
        return "softfail"
    if "?all" in record_lower:
        return "neutral"
    if "+all" in record_lower:
        return "pass"
    return "unknown"


def _check_spf(domain: str, recommendations: List[str]) -> Dict[str, Any]:
    txt_records, failed = _query_txt(domain)

    if failed:
        recommendations.append("Could not verify SPF — DNS lookup timed out.")
        return {"found": False, "record": None, "policy": None, "score": 0}

    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        recommendations.append("SPF not found — add an SPF record.")
        return {"found": False, "record": None, "policy": None, "score": 0}

    record = spf_records[0]
    policy = _spf_policy(record)

    spf_score = 30
    if policy == "softfail":
        spf_score = 20
        recommendations.append("SPF uses softfail (~all) — consider a hard fail (-all) for stronger protection")
    elif policy in ("neutral", "pass"):
        spf_score = 10
        recommendations.append(f"SPF policy is '{policy}' — provides little protection.")

    return {"found": True, "record": record, "policy": policy, "score": spf_score}


def _check_dmarc(domain: str, recommendations: List[str]) -> Dict[str, Any]:
    txt_records, failed = _query_txt(f"_dmarc.{domain}")

    if failed:
        return {"found": False, "record": None, "policy": None, "score": 0}

    dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        recommendations.append("DMARC not found — add a DMARC record.")
        return {"found": False, "record": None, "policy": None, "score": 0}

    record = dmarc_records[0]
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "none").lower()

    dmarc_score = 10
    if policy == "reject":
        dmarc_score = 35
    elif policy == "quarantine":
        dmarc_score = 25
        recommendations.append("DMARC policy is 'quarantine' — failing mail goes to spam.")

    if "rua" not in tags:
        dmarc_score = max(0, dmarc_score - 5)
        recommendations.append("DMARC has no rua= reporting address.")

    return {"found": True, "record": record, "policy": policy, "score": dmarc_score}


def _check_dkim(domain: str, recommendations: List[str]) -> Dict[str, Any]:
    # Combine baseline guesses with dynamically generated infrastructure keys
    dynamic_keys = _discover_dynamic_selectors(domain)
    selectors_to_check = list(set(BASE_DKIM_SELECTORS + dynamic_keys))

    def check_selector(selector: str):
        records, _failed = _query_txt(f"{selector}._domainkey.{domain}")
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
            return selector
        return None

    # Threading prevents the added dynamic keys from slowing down execution time
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(selectors_to_check)) as executor:
        results = executor.map(check_selector, selectors_to_check)
        found_selectors = [s for s in results if s is not None]

    found = len(found_selectors) > 0
    dkim_score = 35 if found else 0

    if not found:
        recommendations.append("DKIM not found — add DKIM record to prevent spoofing")

    return {
        "found": found, 
        "selectors_checked": selectors_to_check,
        "found_selectors": found_selectors,
        "score": dkim_score
    }


def email_security_check(domain: str) -> dict:
    """
    Check SPF, DKIM, and DMARC DNS records for a domain to assess
    basic email anti-spoofing configuration.

    DKIM detection is best-effort here. It checks a fixed list of common
    selectors used by major email providers, since DKIM selectors
    cannot be discovered via DNS without already knowing them.
    """
    domain = domain.strip().lower()

    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    try:
        recommendations: List[str] = []

        spf = _check_spf(domain, recommendations)
        dmarc = _check_dmarc(domain, recommendations)
        dkim = _check_dkim(domain, recommendations)

        raw_score = spf.pop("score") + dmarc.pop("score") + dkim.pop("score")
        
        if recommendations and raw_score == 100:
            raw_score = 90

        if raw_score >= 90:
            rating = "Excellent"
        elif raw_score >= 70:
            rating = "Good"
        elif raw_score >= 40:
            rating = "Fair"
        else:
            rating = "Critical"

        return {
            "success": True,
            "domain": domain,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "security_score": f"{raw_score}%",
            "rating": rating,
            "recommendations": recommendations,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}