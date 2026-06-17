"""HTTP Security Headers Analyzer Tool.

Analyzes the actual values of HTTP security headers and flags
misconfigurations with severity ratings.
"""
from __future__ import annotations

import urllib.request
import urllib.error
import ssl
from typing import Any

from utils.helpers import is_valid_domain


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
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    url = f"https://{domain}"

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "AynOps-HeadersAnalyzer/1.0"})
        # Build an opener that follows redirects (HTTPRedirectHandler is default,
        # but we explicitly ensure it's included) and captures the FINAL response
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPRedirectHandler(),
        )
        with opener.open(req, timeout=10) as resp:
            # resp.url gives us the final URL after redirects
            domain = resp.url.split("/")[2]
            # Normalize all header keys to lowercase for consistent lookup
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.URLError as e:
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
                if max_age < 31536000:
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
        if "default-src 'none'" not in csp_lower and "default-src 'self'" not in csp_lower:
            if not any(d in csp_lower for d in ["default-src 'self'", "default-src 'none'"]):
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
        headers["permissions-policy"] = {
            "present": True,
            "value": pp[:100] + ("..." if len(pp) > 100 else ""),
            "issue": "None",
            "severity": "low",
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

    return {"success": True, "domain": domain, "headers": headers}
