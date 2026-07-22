"""Subdomain Takeover Checker Tool.

Discovers subdomains via the existing DNS enumeration logic, resolves each
subdomain's CNAME record, matches it against known-vulnerable service
fingerprints (GitHub Pages, Heroku, S3, Azure, Ghost, Shopify, Fastly), and
confirms the takeover with an HTTP request checking for the service's
takeover-indicating response.
"""
import dns.resolver
import requests

from tools.dns_tool import PUBLIC_RESOLVERS, dns_enumeration
from utils.helpers import is_valid_domain, normalize_domain

# (cname_contains, service, takeover indicator)
# indicator key "status" matches on the HTTP status code, "body" on response text.
VULNERABLE_FINGERPRINTS = [
    {"cname_contains": "github.io", "service": "GitHub Pages", "indicator": {"body": "There isn't a GitHub Pages site here."}},
    {"cname_contains": "herokuapp.com", "service": "Heroku", "indicator": {"body": "No such app"}},
    {"cname_contains": "amazonaws.com", "service": "AWS S3", "indicator": {"body": "NoSuchBucket"}},
    {"cname_contains": "azurewebsites.net", "service": "Azure", "indicator": {"body": "404 Web Site not found"}},
    {"cname_contains": "ghost.io", "service": "Ghost", "indicator": {"body": "404 Domain Not Found"}},
    {"cname_contains": "myshopify.com", "service": "Shopify", "indicator": {"body": "Sorry, this shop"}},
    {"cname_contains": "fastly.net", "service": "Fastly", "indicator": {"body": "Fastly error"}},
]

_REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}
_REQUEST_TIMEOUT = 10


def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_RESOLVERS
    return resolver


def _resolve_cname(subdomain: str, resolver) -> str | None:
    """Return the subdomain's CNAME target, or None if it has none."""
    try:
        answers = resolver.resolve(subdomain, "CNAME", lifetime=5, tcp=True)
        return str(answers[0]).rstrip(".")
    except Exception:
        return None


def _match_fingerprint(cname: str) -> dict | None:
    cname = cname.lower()
    for fingerprint in VULNERABLE_FINGERPRINTS:
        if fingerprint["cname_contains"] in cname:
            return fingerprint
    return None


def _probe(subdomain: str):
    """Fetch the subdomain over HTTPS first, falling back to HTTP.

    Many hosted services only serve (or redirect to) HTTPS, so try that first
    and fall back to plain HTTP only when the HTTPS connection itself fails.
    Returns the response, or None if neither scheme connects.
    """
    for scheme in ("https", "http"):
        try:
            return requests.get(
                f"{scheme}://{subdomain}",
                headers=_REQUEST_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException:
            continue
    return None


def _confirms_takeover(subdomain: str, fingerprint: dict) -> bool:
    """HTTP-probe the subdomain and check for the takeover-indicating response."""
    response = _probe(subdomain)
    if response is None:
        return False

    indicator = fingerprint["indicator"]
    if "status" in indicator:
        return response.status_code == indicator["status"]
    return indicator["body"] in response.text


def subdomain_takeover(domain: str) -> dict:
    """
    Check discovered subdomains for potential takeover vulnerabilities.
    A subdomain takeover occurs when a subdomain's CNAME points to an external
    service (GitHub Pages, Heroku, S3 etc.) that is no longer active.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    # Subdomain discovery reuses the existing DNS enumeration tool.
    enumeration = dns_enumeration(domain)
    if not enumeration.get("success"):
        return {
            "success": False,
            "error": enumeration.get("error", "DNS enumeration failed"),
        }

    subdomains = enumeration.get("subdomains_found", [])
    resolver = _make_resolver()

    vulnerable = []
    safe = []

    for subdomain in subdomains:
        cname = _resolve_cname(subdomain, resolver)
        if not cname:
            safe.append(subdomain)
            continue

        fingerprint = _match_fingerprint(cname)
        if not fingerprint:
            safe.append(subdomain)
            continue

        if _confirms_takeover(subdomain, fingerprint):
            vulnerable.append({
                "subdomain": subdomain,
                "cname": cname,
                "service": fingerprint["service"],
                "reason": f"CNAME points to unclaimed {fingerprint['service']} service",
                "severity": "HIGH",
            })
        else:
            safe.append(subdomain)

    return {
        "success": True,
        "domain": domain,
        "subdomains_checked": len(subdomains),
        "vulnerable": vulnerable,
        "safe": safe,
        "total_vulnerable": len(vulnerable),
    }
