"""HTTP Security Headers Analyzer Tool.

Analyzes the actual values of HTTP security headers and flags
misconfigurations with severity ratings.
"""
from __future__ import annotations

from urllib.parse import urljoin
from curl_cffi import requests
from curl_cffi.requests.errors import RequestsError
from typing import Any, List, Dict

from utils.helpers import is_valid_domain, normalize_domain

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_MAX_REDIRECT_HOPS = 8

# Sensitive Permissions-Policy features worth flagging when wildcarded
# to all origins. Not exhaustive, these are the ones with the most
# direct privacy/security impact if left unrestricted.
_SENSITIVE_PERMISSIONS_FEATURES = (
    "camera", "microphone", "geolocation", "payment", "usb",
)


def _walk_redirect_chain(url: str, max_hops: int = _MAX_REDIRECT_HOPS) -> List[Dict[str, Any]]:
    """Manually follow redirects one hop at a time, capturing each
    response's status and headers along the way.

    curl_cffi's built-in allow_redirects=True (like every other HTTP
    client's auto-follow) only ever surfaces the FINAL response. If an
    intermediate hop, the redirect response itself carries
    different security headers than the destination ( many sites apply
    a baseline header set at a load-balancer/WAF layer that issues
    the redirect, then different page-specific headers on the destination),
    that's invisible with auto-follow. This was a confirmed, real source
    of "differs from DevTools" reports, since DevTools shows every hop
    in the chain as a separate entry.
    """
    hops: List[Dict[str, Any]] = []
    current_url = url
    seen = set()

    while len(hops) < max_hops:
        if current_url in seen:
            break  # redirect loop guard
        seen.add(current_url)

        resp = requests.get(
            current_url, timeout=10, impersonate="chrome", allow_redirects=False
        )
        hops.append({
            "url": current_url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers.items()),
        })

        if resp.status_code in _REDIRECT_STATUSES:
            location = resp.headers.get("location")
            if not location:
                break
            current_url = urljoin(current_url, location)
            continue
        break

    return hops


def headers_analyzer(domain: str) -> dict:
    """Analyze HTTP security headers for a domain.

    Returns a dict with header analysis including present/absent status,
    actual values, issues found, and severity ratings.

    Parameters
    ----------
    domain
        The domain to analyze (e.g. "example.com")

    Returns
    -------
    dict
        ``{"success": True, "domain": ..., "headers": {...}}`` on success,
        or ``{"success": False, "error": ...}`` on failure.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    requested_url = f"https://{domain}"

    try:
        # impersonate="chrome" matches a real Chrome TLS fingerprint and
        # negotiates modern HTTP (h2/h3) instead of a bare-Python TLS
        # signature over HTTP/1.1. Many sites behind a WAF (Cloudflare
        # especially) serve a JS bot-challenge page instead of the real
        # site to clients that don't look like a real browser at the
        # TLS/protocol level, confirmed against a real production site:
        # a plain non-impersonated client got Cloudflare's challenge page
        # (cf-mitigated: challenge) with its own unrelated security
        # headers, while impersonate="chrome" reached the real site. Same
        # library/pattern already used in crt_sh_tool.py for this reason.
        hops = _walk_redirect_chain(requested_url)

        if not hops:
            return {"success": False, "error": "No response received"}

        final_hop = hops[-1]

        # If the chain ends ON a redirect status, we never actually reached
        # real page content, this happens when a redirect loop is
        # detected (e.g. a misconfigured server that 301s to itself) or
        # when the hop cap is hit mid-chain. Confirmed via testing: without
        # this check, the tool would silently analyze the REDIRECT
        # response's own headers (often minimal/unrelated to the page) as
        # if they were the site's real security configuration, and report
        # redirected=False even though a redirect demonstrably occurred.
        if final_hop["status_code"] in _REDIRECT_STATUSES:
            return {
                "success": False,
                "error": (
                    f"Could not reach final page content -- redirect chain "
                    f"did not resolve (stopped after {len(hops)} hop(s) at "
                    f"a {final_hop['status_code']} response, either due to "
                    f"a redirect loop or exceeding the {_MAX_REDIRECT_HOPS}-hop "
                    f"limit). The headers on that response are not the "
                    f"site's actual configuration."
                ),
            }

        final_url = final_hop["url"]
        domain = final_url.split("/")[2]
        redirected = len(hops) > 1

        # curl_cffi (like the `requests` library it mirrors) already
        # combines a header that appears more than once in a response into
        # one comma-joined value while parsing, matching what DevTools
        # displays. This matters because a header appearing more than once
        # (e.g. two Content-Security-Policy directives layered from
        # different sources, a CDN and the origin server) must not be
        # silently collapsed down to just one of them; every combined
        # directive has to be visible for the analysis below to be
        # accurate.
        raw_headers = {k.lower(): v for k, v in final_hop["headers"].items()}

        # Defensive check: if a WAF challenge still gets through despite
        # impersonation (e.g. a stricter Cloudflare policy, or a different
        # provider), its headers belong to the challenge page, not the
        # site. Analyzing them as if they were the site's real security
        # posture would be actively misleading. cf-mitigated is Cloudflare's
        # own signal for this; confirmed present on a real challenge response
        # observed during investigation.
        if raw_headers.get("cf-mitigated") == "challenge":
            return {
                "success": False,
                "error": (
                    "Received a bot-detection challenge page instead of the "
                    "real site (Cloudflare challenge detected). Headers from "
                    "a challenge page do not reflect the site's actual "
                    "configuration, so no analysis was performed."
                ),
            }

    except RequestsError as e:
        return {"success": False, "error": f"Connection failed: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

    headers: dict[str, Any] = {}

    # --- Strict-Transport-Security ---
    hsts = raw_headers.get("strict-transport-security", "")
    if hsts:
        hsts_lower = hsts.lower()
        issues = []
        severity = "low"
        if "max-age=" in hsts_lower:
            try:
                max_age = int(hsts_lower.split("max-age=")[1].split(";")[0].strip())
                if max_age < 0:
                    issues.append(f"max-age is {max_age}, which is invalid (must be non-negative)")
                    severity = "high"
                elif max_age == 0:
                    issues.append("max-age is 0 — this actively disables HSTS, removing protection")
                    severity = "high"
                elif max_age < 31536000:
                    issues.append(f"max-age is {max_age}, recommend 31536000 (1 year)")
                    severity = "medium"
            except (ValueError, IndexError):
                issues.append("Could not parse max-age value")
                severity = "medium"
        else:
            issues.append("max-age directive is missing")
            severity = "high"
        if "includesubdomains" not in hsts_lower:
            issues.append("includeSubDomains directive is missing")
            if severity == "low":
                severity = "medium"
        headers["strict-transport-security"] = {
            "present": True,
            "value": hsts,
            "issue": "; ".join(issues) if issues else "None",
            "severity": severity,
        }
    else:
        headers["strict-transport-security"] = {
            "present": False,
            "value": "",
            "issue": "HSTS header is missing. Without it, browsers may connect over plain HTTP.",
            "severity": "high",
        }

    # --- Content-Security-Policy ---
    csp = raw_headers.get("content-security-policy", "")
    # Also check report-only variant if no enforcing CSP found
    if not csp:
        csp = raw_headers.get("content-security-policy-report-only", "")
        report_only = True
    else:
        report_only = False
    if csp:
        csp_lower = csp.lower()
        issues = []
        severity = "low"
        if "'unsafe-inline'" in csp_lower:
            issues.append("Contains 'unsafe-inline' which negates XSS protection")
            severity = "high"
        if "'unsafe-eval'" in csp_lower:
            issues.append("Contains 'unsafe-eval' which allows eval()")
            severity = "high"
        if "default-src *" in csp_lower or "script-src *" in csp_lower:
            issues.append("Wildcard (*) source defeats the purpose of CSP")
            severity = "high"
        # A CSP without a restrictive default-src (neither 'self' nor
        # 'none') leaves an implicit fallback that's effectively
        # unrestricted for any directive not explicitly listed.
        if "default-src 'none'" not in csp_lower and "default-src 'self'" not in csp_lower:
            issues.append("No restrictive default-src directive found")
            if severity == "low":
                severity = "medium"
        if report_only:
            issues.insert(0, "CSP is report-only mode — violations are reported but not enforced")
            if severity == "low":
                severity = "medium"
        headers["content-security-policy"] = {
            "present": True,
            "value": csp[:200] + ("..." if len(csp) > 200 else ""),
            "issue": "; ".join(issues) if issues else "None",
            "severity": severity,
        }
    else:
        headers["content-security-policy"] = {
            "present": False,
            "value": "",
            "issue": "CSP header is missing. Without it, no restrictions on resource loading.",
            "severity": "high",
        }

    # --- X-Frame-Options ---
    xfo = raw_headers.get("x-frame-options", "")
    if xfo:
        xfo_upper = xfo.upper().strip()
        if xfo_upper in ("DENY", "SAMEORIGIN"):
            headers["x-frame-options"] = {
                "present": True,
                "value": xfo,
                "issue": "None",
                "severity": "low",
            }
        else:
            headers["x-frame-options"] = {
                "present": True,
                "value": xfo,
                "issue": f"Unexpected value '{xfo}', expected DENY or SAMEORIGIN",
                "severity": "medium",
            }
    else:
        headers["x-frame-options"] = {
            "present": False,
            "value": "",
            "issue": "X-Frame-Options is missing. Page can be embedded in iframes (clickjacking).",
            "severity": "medium",
        }

    # --- X-Content-Type-Options ---
    xcto = raw_headers.get("x-content-type-options", "")
    if xcto and xcto.lower().strip() == "nosniff":
        headers["x-content-type-options"] = {
            "present": True,
            "value": xcto,
            "issue": "None",
            "severity": "low",
        }
    else:
        headers["x-content-type-options"] = {
            "present": False,
            "value": xcto,
            "issue": "X-Content-Type-Options is missing or not set to 'nosniff'. Browsers may MIME-sniff responses.",
            "severity": "medium",
        }

    # --- Referrer-Policy ---
    rp = raw_headers.get("referrer-policy", "")
    if rp:
        rp_lower = rp.lower().strip()
        good_policies = ["no-referrer", "strict-origin-when-cross-origin", "same-origin", "strict-origin"]
        if any(p in rp_lower for p in good_policies):
            headers["referrer-policy"] = {
                "present": True,
                "value": rp,
                "issue": "None",
                "severity": "low",
            }
        else:
            headers["referrer-policy"] = {
                "present": True,
                "value": rp,
                "issue": f"Policy '{rp}' may leak more referrer information than necessary",
                "severity": "medium",
            }
    else:
        headers["referrer-policy"] = {
            "present": False,
            "value": "",
            "issue": "Referrer-Policy is missing. Full referrer URLs may leak to third parties.",
            "severity": "low",
        }

    # --- Permissions-Policy ---
    pp = raw_headers.get("permissions-policy", "")
    if pp:
        pp_lower = pp.lower()
        issues = []
        severity = "low"
        # Previously: presence alone was treated as "issue: None, severity:
        # low", regardless of content. Unlike every other header in this
        # file, which evaluates actual values, not just presence. A policy
        # wildcarding a sensitive feature to all origins (e.g. "camera=*")
        # provides essentially no restriction despite being "present".
        for feature in _SENSITIVE_PERMISSIONS_FEATURES:
            if f"{feature}=*" in pp_lower:
                issues.append(f"'{feature}' is granted to all origins (wildcard) — consider restricting")
                severity = "medium"
        headers["permissions-policy"] = {
            "present": True,
            "value": pp[:100] + ("..." if len(pp) > 100 else ""),
            "issue": "; ".join(issues) if issues else "None",
            "severity": severity,
        }
    else:
        headers["permissions-policy"] = {
            "present": False,
            "value": "",
            "issue": "Permissions-Policy is missing. Powerful browser APIs are unrestricted.",
            "severity": "low",
        }

    # --- Information disclosure headers
    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        val = raw_headers.get(hdr, "")
        if val:
            headers[hdr.lower().replace("-", "_")] = {
                "present": True,
                "value": val,
                "issue": f"{hdr} header exposes technology information",
                "severity": "low",
            }

    return {
        "success": True,
        "domain": domain,
        "requested_url": requested_url,
        "final_url": final_url,
        "redirected": redirected,
        "redirect_chain": [
            {
                "url": h["url"],
                "status_code": h["status_code"],
                "headers": {k.lower(): v for k, v in h["headers"].items()},
            }
            for h in hops
        ],
        "headers": headers,
    }