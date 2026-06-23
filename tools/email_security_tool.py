from __future__ import annotations
import concurrent.futures
import dns.resolver
from typing import Any, Dict, List, Tuple
from utils.helpers import is_valid_domain

# Common DKIM selectors used by major email providers. DKIM selectors
# are arbitrary strings chosen by whoever configures DKIM for a domain,
# there is no DNS record that announces them. This list only covers
# well-known defaults, so found=False is NOT proof DKIM is absent,
# only that none of these specific selectors matched.
COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2",
    "dkim", "mail", "smtp", "s1", "s2", "mandrill", "mxvault",
    "everlytickey1", "everlytickey2", "zoho", "amazonses",
]


def _query_txt(name: str) -> Tuple[List[str], bool]:
    """Return (txt_record_strings, resolution_failed) for a DNS name.

    resolution_failed is True only for inconclusive errors (timeout,
    SERVFAIL, network issues), NOT for NXDOMAIN/NoAnswer, which mean
    the record genuinely doesn't exist. A DNS timeout must never be
    silently treated the same as "record confirmed absent," that
    would be a false claim about the domain's security posture.
    """
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
        records = []
        for r in answers:
            records.append(b"".join(r.strings).decode("utf-8", errors="replace"))
        return records, False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], False
    except Exception:
        return [], True


def _spf_policy(record: str) -> str:
    """Map an SPF record's terminal mechanism to a policy label."""
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
        recommendations.append(
            "Could not verify SPF — DNS lookup timed out or failed. "
            "This result may be incomplete."
        )
        return {"found": False, "record": None, "policy": None}

    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        recommendations.append(
            "SPF not found — add an SPF record to prevent email spoofing"
        )
        return {"found": False, "record": None, "policy": None}

    if len(spf_records) > 1:
        recommendations.append(
            f"Multiple SPF records found ({len(spf_records)}) — RFC 7208 "
            "permits only one, this breaks SPF validation"
        )

    record = spf_records[0]
    policy = _spf_policy(record)

    if policy == "softfail":
        recommendations.append(
            "SPF uses softfail (~all) — consider a hard fail (-all) for stronger protection"
        )
    elif policy in ("neutral", "pass"):
        recommendations.append(
            f"SPF policy is '{policy}' — provides little real protection against spoofing"
        )
    elif policy == "unknown":
        recommendations.append(
            "SPF record has no clear terminal 'all' mechanism — review the record"
        )

    return {"found": True, "record": record, "policy": policy}


def _check_dmarc(domain: str, recommendations: List[str]) -> Dict[str, Any]:
    txt_records, failed = _query_txt(f"_dmarc.{domain}")

    if failed:
        recommendations.append(
            "Could not verify DMARC — DNS lookup timed out or failed. "
            "This result may be incomplete."
        )
        return {"found": False, "record": None, "policy": None}

    dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        recommendations.append(
            "DMARC not found — add a DMARC record to enforce SPF/DKIM failures"
        )
        return {"found": False, "record": None, "policy": None}

    record = dmarc_records[0]
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "none").lower()

    if policy == "none":
        recommendations.append(
            "DMARC policy is 'none' — monitoring-only, failing mail is not blocked"
        )
    elif policy == "quarantine":
        recommendations.append(
            "DMARC policy is 'quarantine' — failing mail goes to spam, not rejected"
        )

    if "rua" not in tags:
        recommendations.append(
            "DMARC has no rua= reporting address — failures aren't visible to you"
        )

    return {"found": True, "record": record, "policy": policy}


def _check_dkim(domain: str, recommendations: List[str]) -> Dict[str, Any]:
    def check_selector(selector: str):
        records, _failed = _query_txt(f"{selector}._domainkey.{domain}")
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
            return selector
        return None

    # Sequential lookups here would be up to 17 * 5s = 85s worst case if
    # every selector times out. Running them in parallel caps it at the
    # slowest single lookup instead.
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(COMMON_DKIM_SELECTORS)) as executor:
        results = executor.map(check_selector, COMMON_DKIM_SELECTORS)
        found_selectors = [s for s in results if s is not None]

    found = len(found_selectors) > 0

    if not found:
        recommendations.append(
            "DKIM not found — add DKIM record to prevent spoofing"
        )

    return {"found": found, "selectors_checked": COMMON_DKIM_SELECTORS}


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

        found_count = sum([spf["found"], dmarc["found"], dkim["found"]])
        security_score = int((found_count / 3) * 100)

        if found_count == 3:
            rating = "Excellent"
        elif found_count == 2:
            rating = "Fair"
        elif found_count == 1:
            rating = "Poor"
        else:
            rating = "Critical"

        return {
            "success": True,
            "domain": domain,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "security_score": f"{security_score}%",
            "rating": rating,
            "recommendations": recommendations,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}