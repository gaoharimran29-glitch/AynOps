from curl_cffi import requests
from curl_cffi.requests.errors import RequestsError 
from typing import Dict, Any, Set
import requests as standard_requests  # Used for the quick fallback API

from utils.helpers import is_valid_domain, normalize_domain

def fetch_from_hackertarget(domain: str) -> Set[str]:
    """
    Rapid passive DNS fallback for when crt.sh times out or crashes.
    Does not require API keys or complex TLS bypassing.
    """
    subdomains = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        # Short timeout because HackerTarget is usually instant
        response = standard_requests.get(url, timeout=10)
        if response.status_code == 200 and "error" not in response.text:
            # HackerTarget returns text data: "subdomain.domain.com,IP"
            for line in response.text.strip().split("\n"):
                if "," in line:
                    subdomain = line.split(",")[0].strip().lower()
                    # Clean up wildcards if any and ensure it belongs to target
                    if subdomain.startswith("*."):
                        subdomain = subdomain[2:]
                    if subdomain.endswith(domain) and subdomain != domain:
                        subdomains.add(subdomain)
    except Exception:
        pass  # Quietly ignore fallback issues so we can process what we have
    return subdomains

def cert_transparency(domain: str) -> Dict[str, Any]:
    """
    Search crt.sh Certificate Transparency logs with browser spoofing,
    and automatically falls back to passive DNS if crt.sh times out.
    """
    domain = domain.strip().lower()

    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {
            "success": False,
            "error": "Invalid domain format"
        }

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    try:
        # Try primary source: crt.sh with Chrome impersonation
        response = requests.get(url, headers=headers, timeout=50, impersonate="chrome")
        response.raise_for_status()
        data = response.json()

        unique_subdomains = set()
        wildcards = set()
        certificates = []
        seen = set()

        for entry in data:
            issuer = entry.get("issuer_name", "Unknown")
            not_before = (entry.get("not_before", "").split("T")[0])
            not_after = (entry.get("not_after", "").split("T")[0])
            names = (entry.get("name_value", "").split("\n"))

            for name in names:
                name = name.strip().lower()

                if not name:
                    continue

                if name.startswith("*."):
                    wildcard_pattern = name[1:]  # "*.example.com" -> ".example.com"
                    if wildcard_pattern.endswith("." + domain) or wildcard_pattern == "." + domain:
                        wildcards.add(wildcard_pattern)
                    continue

                if not name.endswith(domain) or name == domain:
                    continue

                unique_subdomains.add(name)
                cert_key = (name, issuer, not_before, not_after)

                if cert_key in seen:
                    continue
                seen.add(cert_key)

                certificates.append({
                    "subdomain": name,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after
                })

        return {
            "success": True,
            "source": "crt.sh",
            "domain": domain,
            "total_certificates": len(certificates),
            "total_unique_subdomains": len(unique_subdomains),
            "unique_subdomains": sorted(unique_subdomains),
            "wildcards_found": sorted(wildcards),
            "returned_certificates": min(50, len(certificates)),
            "truncated": len(certificates) > 50,
            "certificates": certificates[:50]
        }

    except (RequestsError, ValueError) as e:
        # Primary source failed or timed out! Triggering fallback.
        fallback_subdomains = fetch_from_hackertarget(domain)
        
        if fallback_subdomains:
            return {
                "success": True,
                "source": "hackertarget_fallback",
                "domain": domain,
                "total_certificates": 0,
                "total_unique_subdomains": len(fallback_subdomains),
                "unique_subdomains": sorted(list(fallback_subdomains)),
                "wildcards_found": [],
                "returned_certificates": 0,
                "truncated": False,
                "certificates": [],
                "note": f"Primary source (crt.sh) timed out or failed: {str(e)}. Switched to fallback."
            }
        
        # If fallback also yields absolutely nothing, return the timeout error
        return {
            "success": False,
            "domain": domain,
            "error": f"Primary source failed ({str(e)}) and fallback yielded no results."
        }