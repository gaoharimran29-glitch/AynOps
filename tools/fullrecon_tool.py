from tools.signals.registry import TOOL_REGISTRY
from collections import defaultdict
from utils.helpers import is_valid_domain, normalize_domain
from tools.signals.extractor import extract_signals
import concurrent.futures
from datetime import datetime, timezone

def _format_signals_block(signals: dict) -> str:
    """Format extracted signals into a human-readable summary for the threat analysis prompt"""
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

def full_recon(domain: str) -> dict:
    """Execute all registered reconnaissance tools in dependency-aware waves,
    extract security signals, and build the final threat analysis payload.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    results = {}

    def run(name, fn, *args, **kwargs):
        """Execute a single tool and store its result. Any exception is converted into a standardized error result so one tool cannot stop the scan"""
        try:
            results[name] = fn(*args, **kwargs)
        except Exception as e:
            results[name] = {"success": False, "error": str(e)}

    # Group registered tools by execution wave.
    waves = defaultdict(list)

    # Organize tools into Wave 1, Wave 2 and Wave 3.
    for tool in TOOL_REGISTRY:
        waves[tool["wave"]].append(tool)

    def execute_wave(wave_number):
        """
        Execute all tools assigned to a wave concurrently while honoring
        optional skip conditions defined in the tool registry.
        """

        # Get all tools assigned to this execution wave.
        tools = waves.get(wave_number, [])

        if not tools:
            return

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tools)) as executor:
            futures = []

            for tool in tools:
                # Skip tools whose registry-defined prerequisites are not satisfied.
                if not tool.get("should_run", lambda domain, results: True)(domain, results):
                    results[tool["name"]] = {
                        "success": False,
                        "skipped": True,
                        "reason": tool.get("skip_reason", "Skipped"),
                    }
                    continue

                # Build the arguments required by tool from the current results.
                args = tool["args"](domain, results)
                futures.append(executor.submit(run, tool["name"], tool["fn"], *args))

        concurrent.futures.wait(futures)

    execute_wave(1)
    execute_wave(2)
    execute_wave(3)

    # Record the completion time of the scan.
    scanned_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Derive the list of registered tools for coverage reporting.
    all_tools = [tool["name"] for tool in TOOL_REGISTRY]

    # Record the execution status of every registered tool.
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

    # Summarize tool execution outcomes.
    tools_succeeded = sum(1 for v in tool_coverage.values() if v == "success")
    tools_skipped   = sum(1 for v in tool_coverage.values() if v.startswith("skipped"))
    tools_failed    = sum(1 for v in tool_coverage.values() if v.startswith("failed"))

    # Extract normalized security signals from the raw tool outputs.
    signals = extract_signals(results)

    # Return the complete reconnaissance report.
    return {
        "success": True,
        "domain": domain,
        "scanned_at": scanned_at,
        "mode": "threat_analysis",
        "tool_coverage": tool_coverage,
        "tools_summary": {
            "total": len(all_tools),
            "succeeded": tools_succeeded,
            "skipped": tools_skipped,
            "failed": tools_failed,
        },
        "raw_results": results,
        "pre_extracted_signals": signals,
        "signals_block":_format_signals_block(signals)
    }