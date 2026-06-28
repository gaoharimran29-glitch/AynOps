from tools.whois_tool import whois_lookup
from tools.dns_tool import dns_enumeration
from tools.portscan_tool import port_scan
from tools.ssl_tool import ssl_inspect
from tools.techstack_tool import tech_stack_detect
from tools.asn_tool import asn_lookup
from tools.crt_sh_tool import cert_transparency
from tools.headers_tool import headers_analyzer
from tools.cve_tool import cve_lookup
from tools.iprep_tool import ip_reputation
from tools.email_security_tool import email_security_check
from utils.helpers import is_valid_domain
import concurrent.futures
from datetime import datetime, timezone

THREAT_ANALYSIS_PROMPT = """\
You are a senior penetration tester reviewing raw reconnaissance data collected
from 11 automated tools about the target domain below.

YOUR JOB IS CORRELATION, NOT ENUMERATION.
Do NOT summarise each tool individually.
Instead, weave findings across tools into a single coherent threat picture.
Look especially for combinations that amplify risk — examples:
  • Outdated CMS (techstack) + missing X-Frame-Options (headers) = clickjacking on a CMS
    with known exploits
  • Open port 443 (ports) + SSL cert expiring in < 30 days (ssl) = imminent HTTPS outage
  • Missing DMARC/SPF/DKIM (email_security) + public-facing mail server = trivial spoofing
  • High ASN abuse score (asn) + IP flagged by reputation (ip_reputation) = hosting provider
    actively used for attacks; consider moving infra
  • Many CT-log subdomains (ct_logs) + weak headers on root domain (headers) = broad surface
    with inadequate baseline hardening

Follow this exact output structure — no prose outside it:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️  AynOps Threat Intelligence Report
Target : {domain}
Scanned: {scanned_at}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## Executive Summary
[Exactly 3 sentences:
  1. Overall security posture (one word rating + brief reason)
  2. The single most dangerous finding and what an attacker gains from it
  3. The one action the domain owner must take TODAY]

## 🔴 Critical Findings
[Only issues that are directly exploitable RIGHT NOW or expose sensitive data.
 Use this format for every item:

   **[SHORT TITLE]**
   Risk   : <what an attacker can do — be specific, no vague language>
   Source : <which tool(s) surfaced this>
   Correlated with: <other signal(s) that make this worse, or "None">

 Write "None identified." if nothing qualifies.]

## 🟡 Notable Findings
[Medium/high risk that are not immediately exploitable but increase attack surface.
 Same format as Critical Findings above.
 Include: outdated software, missing security headers, weak TLS, large subdomain
 surface, email spoofing gaps, permissive ASN neighbourhood, and similar.]

## 🟢 What Is Configured Correctly
[3 bullet points MAX. Only include things that are genuinely well configured.
 Skip the section entirely if nothing stands out — do not pad.]

## Risk Score
| Category                        | Score  | Reason (one line)            |
|---------------------------------|--------|------------------------------|
| Open ports exposure             |  X/20  | (0 = No Risk, 20 = Max Risk) |
| Software CVEs                   |  X/25  | (0 = No Risk, 25 = Max Risk) |
| SSL / TLS posture               |  X/20  | (0 = No Risk, 20 = Max Risk) |
| Security headers                |  X/15  | (0 = No Risk, 15 = Max Risk) |
| Email security (SPF/DKIM/DMARC) |  X/10  | (0 = No Risk, 10 = Max Risk) |
| IP / ASN reputation             |  X/5   | (0 = No Risk, 5 = Max Risk)  |
| DNS / subdomain surface         |  X/5   | (0 = No Risk, 5 = Max Risk)  |
| **TOTAL**                       | **X/100** |                         |

Risk Level: CRITICAL (80–100) / HIGH (60–79) / MEDIUM (40–59) / LOW (0–39)
(higher score = more risk)

## Remediation Roadmap
**Immediate — do today (before close of business):**
  1. ...

**This week:**
  1. ...

**This month:**
  1. ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PRE-EXTRACTED SIGNALS (use these; do not re-derive from raw JSON):
{signals_block}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EVIDENCE QUALITY RULES — follow these strictly:
• Never report a vulnerability solely because data is missing from a tool.
• IF the Headers tool returned an HTTP status of 4xx or 5xx, or if the scan returned an empty payload, you MUST classify security headers as "Insufficient data" rather than "Missing". Do not penalize the domain for a blocked or failed request.
• Use this language:
    - "Confirmed" — tool returned explicit evidence
    - "Likely" — strong indirect evidence from correlated tools
    - "Insufficient data" — tool failed, was blocked, or returned no result
• CVSS ≥ 9.0 → always Critical regardless of other context
• CVSS 7.0–8.9 → Notable unless correlated with open port or CMS → then Critical
• ASN or IP reputation abuse score > 50 → always at least Notable
• SSL or domain expiry < 14 days → always Critical
• Missing SPF + missing DMARC → always Critical (trivial spoofing)
• If a tool was skipped or failed, say so in the relevant finding instead of omitting it
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""


def _format_signals_block(signals: dict) -> str:
    """Render the pre-extracted signals dict as a readable block for the prompt."""
    lines = []

    if signals.get("auto_warnings"):
        lines.append("⚠️  AUTO-WARNINGS (highest priority):")
        for w in signals["auto_warnings"]:
            lines.append(f"  • {w}")
        lines.append("")

    lines.append(f"Domain expiry      : {signals.get('domain_expiry_days', 'unknown')} days")
    lines.append(f"SSL days remaining : {signals.get('ssl_days_remaining', 'unknown')} days")
    lines.append(f"Open ports         : {', '.join(signals['open_ports']) or 'none detected'}")
    lines.append(f"Software detected  : {', '.join(signals['software_detected']) or 'none'}")
    lines.append(f"Subdomains (CT)    : {signals.get('subdomain_count', 0)}")
    lines.append(f"IP abuse score     : {signals.get('ip_abuse_score', 0)}/100")
    lines.append(f"IP flagged malicious: {signals.get('ip_reputation_flagged', False)}")

    missing_hdrs = signals.get("missing_security_headers", [])
    lines.append(f"Missing sec headers: {len(missing_hdrs)} — {', '.join(missing_hdrs) or 'none'}")
    lines.append(f"Headers tool state : {signals.get('headers_tool_state', 'unknown')}")

    missing_dns = signals.get("dns_missing_records", [])
    lines.append(f"Missing DNS records : {', '.join(missing_dns) or 'none'}")

    email_sec = signals.get("email_security", {})
    if email_sec:
        lines.append(f"Email security score: {email_sec.get('security_score', 'n/a')} ({email_sec.get('rating', 'n/a')})")
        lines.append(f"  SPF  : {'✓ found' if email_sec.get('spf_found') else '✗ missing'} — policy: {email_sec.get('spf_policy', 'n/a')}")
        lines.append(f"  DKIM : {'✓ found' if email_sec.get('dkim_found') else '✗ missing'}")
        lines.append(f"  DMARC: {'✓ found' if email_sec.get('dmarc_found') else '✗ missing'} — policy: {email_sec.get('dmarc_policy', 'n/a')}")

    cves = signals.get("cves_found", [])
    if cves:
        lines.append(f"CVEs found ({len(cves)}):")
        for c in cves[:5]:
            lines.append(f"  • {c['id']} (CVSS {c['cvss']}) — {c['summary']}")
        if len(cves) > 5:
            lines.append(f"  … and {len(cves) - 5} more")
    else:
        lines.append("CVEs found         : none")

    return "\n".join(lines)

def safe_parse_datetime(date_input) -> datetime | None:
    """Helper to catch and resolve structural variances in string dates."""
    if not date_input:
        return None
    
    # If the input is already a datetime object (some tools return structured objects)
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

def extract_signals(results: dict) -> dict:
    """
    Pull key security signals out of ALL 11 tool results.
    This guides Claude's attention to what matters most
    so nothing gets buried in a wall of JSON.

    Tools covered:
      whois, dns, ports, ssl, techstack, asn, ct_logs, headers,
      email_security, cve, ip_reputation
    """
    signals = {
        # ── per-tool signals ──────────────────────────────────
        "domain_expiry_days":       None,   # whois
        "dns_missing_records":      [],     # dns  (SPF / DMARC / DKIM)
        "open_ports":               [],     # ports
        "ssl_days_remaining":       None,   # ssl
        "software_detected":        [],     # techstack
        "ip_abuse_score":           0,      # asn
        "subdomain_count":          0,      # ct_logs
        "missing_security_headers": [],     # headers
        "email_security":           {},     # email_security_tool
        "cves_found":               [],     # cve  — list of {id, cvss, summary}
        "ip_reputation_flagged":    False,  # ip_reputation
        # ── pre-flagged warnings for Claude ──────────────────
        "auto_warnings":            [],
    }

    # ── 1. WHOIS: domain expiry ───────────────────────────────
    whois = results.get("whois", {})
    if whois.get("success"):
        expiry = whois.get("expiration_date") or whois.get("data", {}).get("expiration_date")
        exp_dt = safe_parse_datetime(expiry)
        if exp_dt:
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            days = (exp_dt - datetime.now(timezone.utc)).days
            signals["domain_expiry_days"] = days
            if days < 0:
                signals["auto_warnings"].append(f"Domain EXPIRED {abs(days)} days ago — domain may be hijackable")
            elif days < 14:
                signals["auto_warnings"].append(f"Domain expires in {days} days — CRITICAL renewal required")
            elif days < 30:
                signals["auto_warnings"].append(f"Domain expires in {days} days — HIGH priority renewal")

    # ── 2. DNS: Check structural connectivity and baseline records ────────────
    dns = results.get("dns", {})
    if dns.get("success"):
        records = dns.get("records", {})
        missing_dns = []

        # Check for core operational routing records
        if not records.get("A") and not records.get("AAAA"):
            missing_dns.append("A/AAAA")
            signals["auto_warnings"].append(
                "No A or AAAA records found — domain may not resolve to an active web server."
            )

        # Check if the domain is missing mail routing capabilities entirely
        if not records.get("MX"):
            missing_dns.append("MX")
            signals["auto_warnings"].append(
                "Missing MX records — this domain cannot natively receive email traffic safely."
            )

        # Log tracked structural gaps (excluding email security features handled by wave 1/3)
        signals["dns_missing_records"] = missing_dns

    # ── 3. PORTS: open port list ──────────────────────────────
    ports_data = results.get("ports", {})
    if ports_data.get("success"):
        open_port_nums = []
        for host in ports_data.get("results", []):
            for proto, port_list in host.get("protocols", {}).items():
                for p in port_list:
                    if p.get("state") == "open":
                        signals["open_ports"].append(
                            f"{p['port']}/tcp ({p.get('service', '?')})"
                        )
                        open_port_nums.append(p.get("port"))

        dangerous = {21: "FTP", 23: "Telnet", 3389: "RDP", 445: "SMB",
                     3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}
        for port_num, service in dangerous.items():
            if port_num in open_port_nums:
                signals["auto_warnings"].append(
                    f"Dangerous port open: {port_num} ({service}) — high-value attack target"
                )

    # ── 4. SSL: days until expiry ─────────────────────────────
    ssl = results.get("ssl", {})
    if ssl.get("success"):
        expiry = ssl.get("expires") or ssl.get("data", {}).get("expires")
        exp_dt = safe_parse_datetime(expiry)
        if exp_dt:
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            days = (exp_dt - datetime.now(timezone.utc)).days
            signals["ssl_days_remaining"] = days
            if days < 0:
                signals["auto_warnings"].append(f"SSL cert EXPIRED {abs(days)} days ago — all HTTPS traffic at risk")
            elif days < 14:
                signals["auto_warnings"].append(f"SSL cert expires in {days} days — CRITICAL, renew immediately")
            elif days < 30:
                signals["auto_warnings"].append(f"SSL cert expires in {days} days — HIGH priority renewal")

    # ── 5. TECHSTACK: software versions ──────────────────────
    ts = results.get("techstack", {})
    if ts.get("success"):
        for key in ["server", "cms", "framework", "language", "cdn"]:
            val = ts.get(key) or ts.get("data", {}).get(key)
            if val and str(val).strip() not in ("Unknown", "None", ""):
                signals["software_detected"].append(str(val).strip())

    # ── 6. ASN: IP abuse score ────────────────────────────────
    asn = results.get("asn", {})
    if asn.get("success"):
        score = asn.get("abuse_score") or asn.get("data", {}).get("abuse_score", 0)
        try:
            score = int(score)
        except (TypeError, ValueError):
            score = 0
        signals["ip_abuse_score"] = score
        if score > 50:
            signals["auto_warnings"].append(
                f"ASN abuse score {score}/100 — HIGH malicious activity reported on this IP range"
            )
        elif score > 20:
            signals["auto_warnings"].append(
                f"ASN abuse score {score}/100 — elevated, investigate hosting provider"
            )

    # ── 7. CT LOGS: subdomain attack surface ─────────────────
    ct = results.get("ct_logs", {})
    if ct.get("success"):
        count = ct.get("total_unique_subdomains", 0)
        signals["subdomain_count"] = count
        if count > 50:
            signals["auto_warnings"].append(
                f"Very large attack surface: {count} subdomains in CT logs"
            )
        elif count > 20:
            signals["auto_warnings"].append(
                f"Expanded attack surface: {count} subdomains found in CT logs"
            )

    # ── 8. HEADERS: missing security headers ─────────────────
    hdrs = results.get("headers", {})
    signals["headers_tool_state"] = "success"  # Default fallback
    
    if hdrs.get("success"):
        # Track HTTP status if your analyzer provides it (e.g., 403 Forbidden)
        status_code = hdrs.get("status_code", 200)
        headers_data = hdrs.get("headers", {})
        
        if status_code >= 400 or not headers_data:
            signals["headers_tool_state"] = f"failed_or_blocked (HTTP {status_code})"
            signals["missing_security_headers"] = [] # Clear out false missing flags
        else:
            missing = []
            for header_name, header_info in headers_data.items():
                if isinstance(header_info, dict) and not header_info.get("present", True):
                    missing.append(header_name.upper())
            signals["missing_security_headers"] = missing
            
            if len(missing) >= 4:
                signals["auto_warnings"].append(
                    f"{len(missing)} security headers missing ({', '.join(missing)}) — significant hardening gap"
                )
            elif len(missing) >= 2:
                signals["auto_warnings"].append(
                    f"{len(missing)} security headers missing: {', '.join(missing)}"
                )
    else:
        signals["headers_tool_state"] = "tool_failed"
        
    # ── 9. EMAIL SECURITY: SPF / DKIM / DMARC deep analysis ──
    # email_security_tool returns full SPF/DKIM/DMARC breakdown with policies and scores
    email_sec = results.get("email_security", {})
    if email_sec.get("success"):
        spf   = email_sec.get("spf",   {})
        dkim  = email_sec.get("dkim",  {})
        dmarc = email_sec.get("dmarc", {})

        spf_found   = spf.get("found", False)
        dkim_found  = dkim.get("found", False)
        dmarc_found = dmarc.get("found", False)
        spf_policy  = spf.get("policy", "none")
        dmarc_policy = dmarc.get("policy", "none")

        signals["email_security"] = {
            "security_score": email_sec.get("security_score", "0%"),
            "rating":         email_sec.get("rating", "Unknown"),
            "spf_found":      spf_found,
            "spf_policy":     spf_policy,
            "dkim_found":     dkim_found,
            "dmarc_found":    dmarc_found,
            "dmarc_policy":   dmarc_policy,
            "recommendations": email_sec.get("recommendations", []),
        }

        if not spf_found and not dmarc_found:
            signals["auto_warnings"].append(
                "No SPF and no DMARC configured — trivial email spoofing, any attacker can "
                "send mail appearing to come from this domain"
            )
        elif not spf_found:
            signals["auto_warnings"].append(
                "SPF missing — senders cannot be validated, enables phishing from this domain"
            )
        elif spf_policy in ("neutral", "pass", "+all"):
            signals["auto_warnings"].append(
                f"SPF policy is '{spf_policy}' — provides no real protection; use '-all'"
            )

        if not dkim_found:
            signals["auto_warnings"].append(
                "DKIM not detected on any common selector — email integrity cannot be verified"
            )

        if not dmarc_found:
            signals["auto_warnings"].append(
                "DMARC missing — receiving mail servers have no policy for handling spoofed mail"
            )
        elif dmarc_policy == "none":
            signals["auto_warnings"].append(
                "DMARC policy is 'none' — monitoring only, spoofed mail is still delivered"
            )

    # ── 10. CVE: known vulnerabilities ────────────────────────
    cve = results.get("cve", {})
    if cve.get("success"):
        cve_list = cve.get("cves") or cve.get("data", {}).get("cves", [])
        for entry in cve_list:
            cve_id   = entry.get("id") or entry.get("cve_id", "")
            cvss     = entry.get("cvss") or entry.get("cvss_score", 0)
            summary  = entry.get("summary") or entry.get("description", "")
            if cve_id:
                signals["cves_found"].append({
                    "id":      cve_id,
                    "cvss":    cvss,
                    "summary": str(summary)[:120],
                })

        critical_cves = [c for c in signals["cves_found"] if float(c.get("cvss") or 0) >= 9.0]
        high_cves     = [c for c in signals["cves_found"] if 7.0 <= float(c.get("cvss") or 0) < 9.0]
        if critical_cves:
            ids = ", ".join(c["id"] for c in critical_cves[:3])
            signals["auto_warnings"].append(
                f"CRITICAL CVEs detected: {ids} (CVSS ≥ 9.0) — immediately exploitable"
            )
        elif high_cves:
            ids = ", ".join(c["id"] for c in high_cves[:3])
            signals["auto_warnings"].append(
                f"High-severity CVEs detected: {ids} (CVSS 7–9) — patch urgently"
            )

    # ── 11. IP REPUTATION: malicious flag ────────────────────
    iprep = results.get("ip_reputation", {})
    if iprep.get("success"):
        flagged    = iprep.get("is_malicious") or iprep.get("data", {}).get("is_malicious", False)
        rep_score  = iprep.get("score") or iprep.get("data", {}).get("score", 0)
        categories = iprep.get("categories") or iprep.get("data", {}).get("categories", [])
        signals["ip_reputation_flagged"] = bool(flagged)
        try:
            rep_score = int(rep_score)
        except (TypeError, ValueError):
            rep_score = 0
        if flagged:
            cat_str = f" ({', '.join(categories[:3])})" if categories else ""
            signals["auto_warnings"].append(
                f"IP flagged as MALICIOUS by reputation service{cat_str} "
                f"— hosting may be blacklisted by mail servers and firewalls"
            )
        elif rep_score > 20:
            signals["auto_warnings"].append(
                f"IP reputation score {rep_score}/100 — elevated risk, monitor closely"
            )

    return signals


def ct_summary(domain: str) -> dict:
    """Lightweight CT log summary — avoids returning thousands of certs."""
    result = cert_transparency(domain)
    if not result.get("success"):
        return result
    return {
        "success": True,
        "total_unique_subdomains": result.get(
            "total_unique_subdomains",
            len(result.get("unique_subdomains", []))
        ),
        "sample_subdomains": result.get("unique_subdomains", [])[:50],
    }


def _extract_ip(results: dict, domain: str) -> str | None:
    """
    Extract IP address from results using multiple fallbacks.
    Priority: ASN result → DNS A record → None
    """
    asn = results.get("asn", {})
    if asn.get("success"):
        ip = asn.get("ip") or asn.get("data", {}).get("ip")
        if ip:
            return str(ip).strip()

    dns = results.get("dns", {})
    if dns.get("success"):
        a_records = dns.get("records", {}).get("A", [])
        if a_records:
            return str(a_records[0]).strip()

    return None


def _extract_software(results: dict) -> tuple[str, str]:
    """
    Extract software name and version from techstack or ports.
    Returns (software, version) tuple.
    """
    ts = results.get("techstack", {})
    if ts.get("success"):
        server  = ts.get("server")  or ts.get("data", {}).get("server",  "")
        version = ts.get("server_version") or ts.get("data", {}).get("server_version", "")
        if server and server.lower() not in ("unknown", "none", ""):
            return str(server).strip(), str(version).strip()

    ports = results.get("ports", {})
    if ports.get("success"):
        for host in ports.get("results", []):
            for proto, port_list in host.get("protocols", {}).items():
                for p in port_list:
                    if p.get("state") == "open":
                        service = p.get("service", "")
                        version = p.get("version", "")
                        if service and service not in ("http", "https", "unknown"):
                            return service, version

    return "", ""


def full_recon(domain: str) -> dict:
    """
    Run ALL 11 recon tools on a domain in three waves to prevent network rate-limiting.
    """
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    results = {}

    def run(name, fn, *args, **kwargs):
        try:
            results[name] = fn(*args, **kwargs)
        except Exception as e:
            results[name] = {"success": False, "error": str(e)}

    # ── Wave 1: Lightweight API & Infrastructure Records ─────────────────────
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures = [
            ex.submit(run, "whois",          whois_lookup,        domain),
            ex.submit(run, "dns",            dns_enumeration,     domain),
            ex.submit(run, "ssl",            ssl_inspect,         domain),
            ex.submit(run, "headers",        headers_analyzer,    domain),
            ex.submit(run, "email_security", email_security_check, domain),
            ex.submit(run, "asn" , asn_lookup , domain)
        ]
        concurrent.futures.wait(futures)

    # ── Wave 2: Aggressive Port/Tech Scans & Throttled Log Aggregators ───────
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures = [
            ex.submit(run, "ports",          port_scan,           domain, "service"),
            ex.submit(run, "techstack",      tech_stack_detect,   domain),
            ex.submit(run, "ct_logs",        ct_summary,          domain),  # Separated to avoid rate-limiting
        ]
        concurrent.futures.wait(futures)

    # ── Wave 3: Threat Feeds & Enrichment Data (Depends on Wave 1 & 2) ───────
    software, version = _extract_software(results)
    ip = _extract_ip(results, domain)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        futures = []

        if software:
            futures.append(ex.submit(run, "cve", cve_lookup, software, version))
        else:
            results["cve"] = {
                "success": False,
                "skipped": True,
                "reason": "No software detected in techstack or port scan — CVE lookup skipped",
            }

        if ip:
            futures.append(ex.submit(run, "ip_reputation", ip_reputation, ip))
        else:
            results["ip_reputation"] = {
                "success": False,
                "skipped": True,
                "reason": "No IP address found — ip_reputation skipped",
            }

        if futures:
            concurrent.futures.wait(futures)

    scanned_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # ── Tool coverage audit ────────────────────────────────────
    all_tools = [
    "whois", "dns", "ports", "ssl", "techstack",
    "asn", "ct_logs", "headers", "email_security", "cve", "ip_reputation",
    ]

    tool_coverage = {}
    for tool in all_tools:
        r = results.get(tool, {})
        if r.get("success"):
            tool_coverage[tool] = "success"
        elif r.get("skipped"):
            tool_coverage[tool] = f"skipped — {r.get('reason', '')}"
        elif "error" in r:
            tool_coverage[tool] = f"failed — {r.get('error', '')}"
        else:
            tool_coverage[tool] = "no result"

    tools_succeeded = sum(1 for v in tool_coverage.values() if v == "success")
    tools_skipped   = sum(1 for v in tool_coverage.values() if v.startswith("skipped"))
    tools_failed    = sum(1 for v in tool_coverage.values() if v.startswith("failed"))

    signals = extract_signals(results)

    return {
        "success":               True,
        "domain":                domain,
        "scanned_at":            scanned_at,
        "mode":                  "threat_analysis",
        "tool_coverage":         tool_coverage,
        "tools_summary":         {
            "total":     len(all_tools),
            "succeeded": tools_succeeded,
            "skipped":   tools_skipped,
            "failed":    tools_failed,
        },
        "raw_results":           results,
        "pre_extracted_signals": signals,
        "instructions":          THREAT_ANALYSIS_PROMPT.format(
                                     domain=domain,
                                     scanned_at=scanned_at,
                                     signals_block=_format_signals_block(signals),
                                 ),
    }