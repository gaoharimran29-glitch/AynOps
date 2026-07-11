"""HTTP Redirect Chain Tracer Tool.

Manually follows a redirect chain hop by hop, recording each response's
status code and destination, and flags security-relevant patterns along
the way (TLS downgrade, private IPs, redirect loops, cross-domain hops,
excessively long chains).
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urljoin, urlparse
from typing import Any, Dict, List, Optional

import requests

from utils.helpers import is_valid_domain

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_MAX_HOPS = 15
_LONG_CHAIN_THRESHOLD = 5
_REQUEST_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}


def _hostname_is_private_ip(hostname: Optional[str]) -> bool:
    """Return True if hostname is a literal IP address in a private,
    loopback, or link-local range.

    This checks the literal hostname string, not a DNS-resolved
    address, e.g. it flags "http://10.0.5.23/", not "http://
    internal-service.example.com/" even if that name happens to
    resolve to a private IP. Resolving every hop's hostname would add
    latency and its own class of edge cases (DNS rebinding, multiple
    A records). The issue's own wording ("private IP appearing in
    redirect URL") describes a literal-URL check, not a resolved one.
    """
    if not hostname:
        return False
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _strip_www(hostname: str) -> str:
    """Strip a leading "www." for cross-domain comparison purposes.

    Without this, the single most common redirect pattern on the
    internet -- example.com -> www.example.com -- would be flagged as
    "cross-domain" on every single trace, which is noise. This only handles
    the www<->bare case, it does not do full registrable-domain comparison 
    (e.g. sub.example.co.uk vs example.co.uk), which would require a public
    suffix list, a new dependency the issue explicitly asks to avoid. A deeper
    subdomain change (sub.example.com -> example.com) is still flagged, which
    is the conservative/safe direction to err in for a security tool.
    """
    return hostname[4:] if hostname.lower().startswith("www.") else hostname


def _normalize_url(url: str) -> str:
    """Prepend http:// if no scheme is given.

    Deliberately defaults to http://, not https://: the entire point
    of this tool is to detect whether a domain upgrades HTTP to HTTPS
    on its own. Defaulting to https:// would silently skip past a
    domain that never upgrades at all.
    """
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    return url


def trace_redirects(url: str) -> dict:
    """Trace the full redirect chain for a URL, hop by hop.

    Follows redirects manually (allow_redirects=False + loop) instead
    of relying on requests' built-in auto-follow, so each hop's own
    status code and destination are visible. Flags TLS downgrades,
    private-IP destinations, redirect loops, excessively long chains,
    and cross-domain hops along the way.
    """
    original_url = _normalize_url(url)

    parsed = urlparse(original_url)
    if not parsed.hostname or not is_valid_domain(parsed.hostname):
        return {"success": False, "error": "Invalid domain format"}

    chain: List[Dict[str, Any]] = []
    issues_found: List[Dict[str, Any]] = []
    seen_urls = set()
    current_url = original_url
    session = requests.Session()

    try:
        for hop_number in range(1, _MAX_HOPS + 1):
            if current_url in seen_urls:
                # hop_number here is the iteration that WOULD have fetched
                # current_url again, no chain entry is ever recorded for
                # it (we break before fetching). Using hop_number directly
                # would point one past the end of `chain`, since the last
                # real entry is chain[len(chain)-1] with hop == len(chain).
                # len(chain) correctly identifies the last recorded hop,
                # the one whose redirect_to points at the now-repeated URL.
                issues_found.append({
                    "hop": len(chain),
                    "type": "redirect_loop",
                    "severity": "medium",
                    "description": f"Redirect loop detected — {current_url} was already visited in this chain",
                })
                break
            seen_urls.add(current_url)

            resp = session.get(
                current_url, allow_redirects=False, timeout=10, headers=_REQUEST_HEADERS
            )
            status_code = resp.status_code
            current_parsed = urlparse(current_url)

            hop_entry: Dict[str, Any] = {
                "hop": hop_number,
                "url": current_url,
                "status_code": status_code,
                "redirect_to": None,
                "issue": None,
            }

            if status_code in _REDIRECT_STATUSES:
                location = resp.headers.get("Location")
                if not location:
                    hop_entry["issue"] = "Redirect status with no Location header — chain cannot continue"
                    chain.append(hop_entry)
                    issues_found.append({
                        "hop": hop_number,
                        "type": "malformed_redirect",
                        "severity": "low",
                        "description": hop_entry["issue"],
                    })
                    break

                next_url = urljoin(current_url, location)
                hop_entry["redirect_to"] = next_url
                next_parsed = urlparse(next_url)

                hop_issues = []

                if current_parsed.scheme == "https" and next_parsed.scheme == "http":
                    hop_issues.append("HTTPS to HTTP downgrade")
                    issues_found.append({
                        "hop": hop_number, "type": "tls_downgrade", "severity": "critical",
                        "description": f"Downgrades from HTTPS to HTTP: {current_url} -> {next_url}",
                    })
                elif current_parsed.scheme == "http" and next_parsed.scheme == "http":
                    hop_issues.append("HTTP to HTTP redirect (no TLS upgrade)")
                    issues_found.append({
                        "hop": hop_number, "type": "no_tls_upgrade", "severity": "high",
                        "description": f"Stays on HTTP, never upgrades to HTTPS: {current_url} -> {next_url}",
                    })

                is_private_target = _hostname_is_private_ip(next_parsed.hostname)
                if is_private_target:
                    hop_issues.append("Redirects to a private/internal IP address")
                    issues_found.append({
                        "hop": hop_number, "type": "private_ip_leak", "severity": "high",
                        "description": (
                            f"Redirect target's hostname is a private/internal IP: "
                            f"{next_parsed.hostname}. Trace halted here — this tool "
                            f"does not follow redirects into private/internal address "
                            f"space, since doing so would make the tool itself an SSRF "
                            f"vector for whatever host it runs on."
                        ),
                    })

                if (
                    current_parsed.hostname
                    and next_parsed.hostname
                    and _strip_www(current_parsed.hostname) != _strip_www(next_parsed.hostname)
                ):
                    hop_issues.append("Redirects to a different domain — verify this is intended")
                    issues_found.append({
                        "hop": hop_number, "type": "cross_domain_redirect", "severity": "high",
                        "description": (
                            f"Redirects to a different domain: {current_parsed.hostname} -> "
                            f"{next_parsed.hostname}. This is flagged for review -- it is common "
                            f"and legitimate for URL shorteners, domain migrations, and OAuth "
                            f"flows, but can also indicate an unvalidated open-redirect endpoint."
                        ),
                    })

                hop_entry["issue"] = "; ".join(hop_issues) if hop_issues else None
                chain.append(hop_entry)

                if is_private_target:
                    break

                current_url = next_url
                continue

            chain.append(hop_entry)
            break

        else:
            issues_found.append({
                "hop": len(chain),
                "type": "max_hops_exceeded",
                "severity": "medium",
                "description": f"Redirect chain exceeded the {_MAX_HOPS}-hop limit without resolving",
            })

    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Connection failed: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

    total_hops = len(chain)
    if total_hops > _LONG_CHAIN_THRESHOLD:
        issues_found.append({
            "hop": None,
            "type": "long_chain",
            "severity": "low",
            "description": f"Chain has {total_hops} hops, longer than the recommended {_LONG_CHAIN_THRESHOLD} (SEO/performance impact)",
        })

    final_url = chain[-1]["url"] if chain else original_url

    security_notes = []
    has_downgrade = any(i["type"] == "tls_downgrade" for i in issues_found)
    has_no_upgrade = any(i["type"] == "no_tls_upgrade" for i in issues_found)
    if not has_downgrade and not has_no_upgrade:
        if original_url.startswith("http://") and final_url.startswith("https://"):
            security_notes.append("HTTP to HTTPS upgrade present — good")
        elif original_url.startswith("https://"):
            security_notes.append("Chain stayed on HTTPS throughout — good")
    if not any(i["type"] == "private_ip_leak" for i in issues_found):
        security_notes.append("No internal hostnames leaked in chain")

    return {
        "success": True,
        "original_url": original_url,
        "final_url": final_url,
        "total_hops": total_hops,
        "chain": chain,
        "issues_found": issues_found,
        "security_notes": security_notes,
    }