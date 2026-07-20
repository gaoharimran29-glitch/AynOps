from tools.signals.registry import TOOL_REGISTRY

def extract_signals(results):
    """Run each tool's extractor to build a shared signals dictionary."""

    signals = {
    # ── per-tool signals ──────────────────────────────────
    "domain_expiry_days":       None,   # whois``
    "dns_missing_records":      [],     # dns  (SPF / DMARC / DKIM)
    "open_ports":               [],     # ports
    "ssl_days_remaining":       None,   # ssl
    "software_detected":        [],     # techstack
    "ip_abuse_score":           0,      # ip_reputation
    "subdomain_count":          0,      # ct_logs
    "missing_security_headers": [],     # headers
    "email_security":           {},     # email_security_tool
    "ip_reputation_flagged":    False,  # ip_reputation
    "asn_number":               None,   # asn
    "asn_org":                  None,   # asn
    "asn_isp":                  None,   # asn (legacy/org alias when present)
    "asn_country":              None,   # asn
    # ── pre-flagged warnings for Claude ──────────────────
    "auto_warnings":            [],
    }

    for tool in TOOL_REGISTRY:
        extractor = tool.get("extractor")
        if not extractor:
            continue

        result = results.get(tool["name"])
        extractor(result, signals)

    return signals