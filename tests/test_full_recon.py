import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tools.fullrecon_tool import (
    safe_parse_datetime,
    _format_signals_block,
    extract_signals,
    ct_summary,
    _extract_ip,
    _extract_software,
    full_recon,
    THREAT_ANALYSIS_PROMPT,
)

# ===========================================================================
# Fixtures & helpers
# ===========================================================================

def _future_iso(days: int) -> str:
    """Return an ISO-8601 UTC string <days> from now."""
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return dt.isoformat()


def _past_iso(days: int) -> str:
    """Return an ISO-8601 UTC string <days> ago."""
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.isoformat()


def _minimal_signals() -> dict:
    """Return the baseline signals structure with all safe defaults."""
    return {
        "domain_expiry_days":       None,
        "dns_missing_records":      [],
        "open_ports":               [],
        "ssl_days_remaining":       None,
        "software_detected":        [],
        "ip_abuse_score":           0,
        "subdomain_count":          0,
        "missing_security_headers": [],
        "headers_tool_state":       "success",
        "email_security":           {},
        "cves_found":               [],
        "ip_reputation_flagged":    False,
        "auto_warnings":            [],
    }


# ===========================================================================
# 1.  safe_parse_datetime
# ===========================================================================

class TestSafeParseDatetime:

    def test_none_input_returns_none(self):
        assert safe_parse_datetime(None) is None

    def test_empty_string_returns_none(self):
        assert safe_parse_datetime("") is None

    def test_datetime_object_passthrough(self):
        dt = datetime(2030, 1, 1, tzinfo=timezone.utc)
        assert safe_parse_datetime(dt) is dt

    def test_iso_with_z_suffix(self):
        result = safe_parse_datetime("2030-06-15T12:00:00Z")
        assert result is not None
        assert result.year == 2030
        assert result.month == 6

    def test_iso_with_plus_offset(self):
        result = safe_parse_datetime("2030-06-15T12:00:00+05:30")
        assert result is not None
        assert result.year == 2030

    def test_date_only_string(self):
        result = safe_parse_datetime("2030-12-31")
        assert result is not None
        assert result.year == 2030
        assert result.day == 31

    def test_space_separated_with_offset(self):
        result = safe_parse_datetime("2030-06-15 12:00:00+00:00")
        assert result is not None

    def test_space_separated_no_timezone(self):
        result = safe_parse_datetime("2030-06-15 12:00:00")
        assert result is not None

    def test_completely_garbage_string_returns_none(self):
        assert safe_parse_datetime("not-a-date-at-all!!") is None

    def test_numeric_input_converted_to_string(self):
        # Should not crash; may return None
        result = safe_parse_datetime(20301231)
        # Just ensure no exception
        assert result is None or isinstance(result, datetime)

    def test_naive_datetime_object_passthrough(self):
        dt = datetime(2030, 1, 1)  # no tzinfo
        assert safe_parse_datetime(dt) is dt


# ===========================================================================
# 2.  _format_signals_block
# ===========================================================================

class TestFormatSignalsBlock:

    def test_no_warnings_no_email_no_cves(self):
        signals = _minimal_signals()
        signals["open_ports"] = ["80/tcp (http)"]
        signals["software_detected"] = ["nginx"]
        signals["subdomain_count"] = 5
        text = _format_signals_block(signals)
        assert "Open ports" in text
        assert "80/tcp (http)" in text
        assert "nginx" in text
        assert "CVEs found" in text
        assert "none" in text.lower()

    def test_auto_warnings_appear_at_top(self):
        signals = _minimal_signals()
        signals["auto_warnings"] = ["Domain EXPIRED 3 days ago", "SSL cert EXPIRED 1 days ago"]
        text = _format_signals_block(signals)
        lines = text.splitlines()
        # warnings block must appear before domain expiry line
        warn_idx  = next(i for i, l in enumerate(lines) if "AUTO-WARNINGS" in l)
        expiry_idx = next(i for i, l in enumerate(lines) if "Domain expiry" in l)
        assert warn_idx < expiry_idx

    def test_cves_capped_at_five_with_overflow_message(self):
        signals = _minimal_signals()
        signals["cves_found"] = [
            {"id": f"CVE-2024-{n:04d}", "cvss": 9.0, "summary": "desc"} for n in range(8)
        ]
        text = _format_signals_block(signals)
        assert "… and 3 more" in text

    def test_exactly_five_cves_no_overflow(self):
        signals = _minimal_signals()
        signals["cves_found"] = [
            {"id": f"CVE-2024-{n:04d}", "cvss": 7.5, "summary": "desc"} for n in range(5)
        ]
        text = _format_signals_block(signals)
        assert "more" not in text

    def test_email_security_block_rendered(self):
        signals = _minimal_signals()
        signals["email_security"] = {
            "security_score": "80%",
            "rating":         "Good",
            "spf_found":      True,
            "spf_policy":     "-all",
            "dkim_found":     False,
            "dmarc_found":    True,
            "dmarc_policy":   "reject",
        }
        text = _format_signals_block(signals)
        assert "SPF" in text
        assert "DKIM" in text
        assert "DMARC" in text
        assert "✓ found" in text
        assert "✗ missing" in text

    def test_missing_headers_count_displayed(self):
        signals = _minimal_signals()
        signals["missing_security_headers"] = ["CSP", "X-FRAME-OPTIONS", "HSTS"]
        text = _format_signals_block(signals)
        assert "3" in text
        assert "CSP" in text


# ===========================================================================
# 3.  extract_signals
# ===========================================================================

class TestExtractSignals:

    # ── 3.1 WHOIS ──────────────────────────────────────────────────────────

    def test_whois_domain_expiry_future(self):
        results = {"whois": {"success": True, "expiration_date": _future_iso(60)}}
        sig = extract_signals(results)
        assert sig["domain_expiry_days"] is not None
        assert sig["domain_expiry_days"] > 0

    def test_whois_critical_warning_under_14_days(self):
        results = {"whois": {"success": True, "expiration_date": _future_iso(7)}}
        sig = extract_signals(results)
        warnings = " ".join(sig["auto_warnings"])
        assert "CRITICAL" in warnings or "expires in" in warnings

    def test_whois_high_warning_under_30_days(self):
        results = {"whois": {"success": True, "expiration_date": _future_iso(20)}}
        sig = extract_signals(results)
        warnings = " ".join(sig["auto_warnings"])
        assert "expires in" in warnings

    def test_whois_expired_domain_warning(self):
        results = {"whois": {"success": True, "expiration_date": _past_iso(3)}}
        sig = extract_signals(results)
        warnings = " ".join(sig["auto_warnings"])
        assert "EXPIRED" in warnings

    def test_whois_failure_no_crash(self):
        sig = extract_signals({"whois": {"success": False}})
        assert sig["domain_expiry_days"] is None

    def test_whois_nested_data_key(self):
        results = {"whois": {"success": True, "data": {"expiration_date": _future_iso(100)}}}
        sig = extract_signals(results)
        assert sig["domain_expiry_days"] is not None

    # ── 3.2 DNS ────────────────────────────────────────────────────────────

    def test_dns_missing_a_aaaa_adds_warning(self):
        results = {"dns": {"success": True, "records": {}}}
        sig = extract_signals(results)
        assert "A/AAAA" in sig["dns_missing_records"]
        assert any("A or AAAA" in w for w in sig["auto_warnings"])

    def test_dns_missing_mx_adds_warning(self):
        results = {"dns": {"success": True, "records": {"A": ["1.2.3.4"]}}}
        sig = extract_signals(results)
        assert "MX" in sig["dns_missing_records"]

    def test_dns_all_records_present_no_warnings(self):
        results = {
            "dns": {
                "success": True,
                "records": {"A": ["1.2.3.4"], "MX": ["mail.example.com"]},
            }
        }
        sig = extract_signals(results)
        assert sig["dns_missing_records"] == []
        assert not any("A or AAAA" in w or "MX" in w for w in sig["auto_warnings"])

    def test_dns_failure_no_crash(self):
        sig = extract_signals({"dns": {"success": False}})
        assert sig["dns_missing_records"] == []

    # ── 3.3 PORTS ──────────────────────────────────────────────────────────

    def _ports_result(self, port_num: int, service: str) -> dict:
        return {
            "success": True,
            "results": [
                {
                    "protocols": {
                        "tcp": [
                            {"port": port_num, "state": "open", "service": service}
                        ]
                    }
                }
            ],
        }

    def test_open_port_added_to_signals(self):
        results = {"ports": self._ports_result(80, "http")}
        sig = extract_signals(results)
        assert any("80" in p for p in sig["open_ports"])

    def test_dangerous_port_ftp_triggers_warning(self):
        results = {"ports": self._ports_result(21, "ftp")}
        sig = extract_signals(results)
        assert any("21" in w and "FTP" in w for w in sig["auto_warnings"])

    def test_dangerous_port_rdp_triggers_warning(self):
        results = {"ports": self._ports_result(3389, "rdp")}
        sig = extract_signals(results)
        assert any("3389" in w and "RDP" in w for w in sig["auto_warnings"])

    def test_safe_port_no_warning(self):
        results = {"ports": self._ports_result(443, "https")}
        sig = extract_signals(results)
        # 443 is not in the dangerous set
        dangerous_warnings = [w for w in sig["auto_warnings"] if "443" in w]
        assert not dangerous_warnings

    def test_closed_port_ignored(self):
        results = {
            "ports": {
                "success": True,
                "results": [
                    {"protocols": {"tcp": [{"port": 21, "state": "closed", "service": "ftp"}]}}
                ],
            }
        }
        sig = extract_signals(results)
        assert sig["open_ports"] == []

    def test_ports_failure_no_crash(self):
        sig = extract_signals({"ports": {"success": False}})
        assert sig["open_ports"] == []

    # ── 3.4 SSL ────────────────────────────────────────────────────────────

    def test_ssl_days_remaining_calculated(self):
        results = {"ssl": {"success": True, "expires": _future_iso(45)}}
        sig = extract_signals(results)
        assert sig["ssl_days_remaining"] is not None
        assert sig["ssl_days_remaining"] > 0

    def test_ssl_expired_warning(self):
        results = {"ssl": {"success": True, "expires": _past_iso(5)}}
        sig = extract_signals(results)
        assert any("SSL cert EXPIRED" in w for w in sig["auto_warnings"])

    def test_ssl_critical_under_14_days(self):
        results = {"ssl": {"success": True, "expires": _future_iso(10)}}
        sig = extract_signals(results)
        assert any("CRITICAL" in w for w in sig["auto_warnings"])

    def test_ssl_high_under_30_days(self):
        results = {"ssl": {"success": True, "expires": _future_iso(25)}}
        sig = extract_signals(results)
        assert any("HIGH" in w for w in sig["auto_warnings"])

    def test_ssl_failure_no_crash(self):
        sig = extract_signals({"ssl": {"success": False}})
        assert sig["ssl_days_remaining"] is None

    # ── 3.5 TECHSTACK ──────────────────────────────────────────────────────

    def test_techstack_server_detected(self):
        results = {"techstack": {"success": True, "server": "nginx", "cms": "WordPress"}}
        sig = extract_signals(results)
        assert "nginx" in sig["software_detected"]
        assert "WordPress" in sig["software_detected"]

    def test_techstack_unknown_values_excluded(self):
        results = {
            "techstack": {
                "success": True,
                "server":    "Unknown",
                "cms":       "None",
                "framework": "",
            }
        }
        sig = extract_signals(results)
        assert sig["software_detected"] == []

    def test_techstack_failure_no_crash(self):
        sig = extract_signals({"techstack": {"success": False}})
        assert sig["software_detected"] == []

    # ── 3.6 ASN ────────────────────────────────────────────────────────────

    def test_asn_abuse_score_stored(self):
        results = {"asn": {"success": True, "abuse_score": 35}}
        sig = extract_signals(results)
        assert sig["ip_abuse_score"] == 35

    def test_asn_score_over_50_critical_warning(self):
        results = {"asn": {"success": True, "abuse_score": 75}}
        sig = extract_signals(results)
        assert any("HIGH malicious" in w for w in sig["auto_warnings"])

    def test_asn_score_over_20_elevated_warning(self):
        results = {"asn": {"success": True, "abuse_score": 30}}
        sig = extract_signals(results)
        assert any("elevated" in w for w in sig["auto_warnings"])

    def test_asn_score_zero_no_warning(self):
        results = {"asn": {"success": True, "abuse_score": 0}}
        sig = extract_signals(results)
        asn_warnings = [w for w in sig["auto_warnings"] if "ASN" in w]
        assert not asn_warnings

    def test_asn_non_numeric_score_defaults_to_zero(self):
        results = {"asn": {"success": True, "abuse_score": "N/A"}}
        sig = extract_signals(results)
        assert sig["ip_abuse_score"] == 0

    # ── 3.7 CT LOGS ────────────────────────────────────────────────────────

    def test_ct_logs_subdomain_count_stored(self):
        results = {"ct_logs": {"success": True, "total_unique_subdomains": 10}}
        sig = extract_signals(results)
        assert sig["subdomain_count"] == 10

    def test_ct_logs_over_50_very_large_warning(self):
        results = {"ct_logs": {"success": True, "total_unique_subdomains": 60}}
        sig = extract_signals(results)
        assert any("Very large" in w for w in sig["auto_warnings"])

    def test_ct_logs_over_20_expanded_warning(self):
        results = {"ct_logs": {"success": True, "total_unique_subdomains": 25}}
        sig = extract_signals(results)
        assert any("Expanded" in w for w in sig["auto_warnings"])

    def test_ct_logs_failure_no_crash(self):
        sig = extract_signals({"ct_logs": {"success": False}})
        assert sig["subdomain_count"] == 0

    # ── 3.8 HEADERS ────────────────────────────────────────────────────────

    def test_headers_missing_headers_collected(self):
        results = {
            "headers": {
                "success": True,
                "status_code": 200,
                "headers": {
                    "Content-Security-Policy": {"present": False},
                    "X-Frame-Options":          {"present": False},
                    "Strict-Transport-Security": {"present": True},
                },
            }
        }
        sig = extract_signals(results)
        assert "CONTENT-SECURITY-POLICY" in sig["missing_security_headers"]
        assert "X-FRAME-OPTIONS" in sig["missing_security_headers"]
        assert "STRICT-TRANSPORT-SECURITY" not in sig["missing_security_headers"]

    def test_headers_4xx_clears_missing_list(self):
        results = {
            "headers": {
                "success": True,
                "status_code": 403,
                "headers": {"Content-Security-Policy": {"present": False}},
            }
        }
        sig = extract_signals(results)
        assert sig["missing_security_headers"] == []
        assert "blocked" in sig["headers_tool_state"]

    def test_headers_4_or_more_missing_triggers_warning(self):
        headers_data = {
            f"Header-{i}": {"present": False} for i in range(4)
        }
        results = {
            "headers": {"success": True, "status_code": 200, "headers": headers_data}
        }
        sig = extract_signals(results)
        assert any("hardening gap" in w for w in sig["auto_warnings"])

    def test_headers_tool_failure_sets_state(self):
        results = {"headers": {"success": False}}
        sig = extract_signals(results)
        assert sig["headers_tool_state"] == "tool_failed"

    # ── 3.9 EMAIL SECURITY ─────────────────────────────────────────────────

    def _email_result(self, spf=True, dkim=True, dmarc=True,
                      spf_policy="-all", dmarc_policy="reject") -> dict:
        return {
            "success":        True,
            "security_score": "100%",
            "rating":         "Excellent",
            "spf":   {"found": spf,   "policy": spf_policy},
            "dkim":  {"found": dkim},
            "dmarc": {"found": dmarc, "policy": dmarc_policy},
        }

    def test_email_all_present_no_warnings(self):
        results = {"email_security": self._email_result()}
        sig = extract_signals(results)
        email_warnings = [w for w in sig["auto_warnings"] if "SPF" in w or "DKIM" in w or "DMARC" in w]
        assert not email_warnings

    def test_email_no_spf_no_dmarc_critical_warning(self):
        results = {"email_security": self._email_result(spf=False, dmarc=False)}
        sig = extract_signals(results)
        assert any("trivial email spoofing" in w for w in sig["auto_warnings"])

    def test_email_missing_spf_only(self):
        results = {"email_security": self._email_result(spf=False)}
        sig = extract_signals(results)
        assert any("SPF missing" in w for w in sig["auto_warnings"])

    def test_email_weak_spf_policy_plusall(self):
        results = {"email_security": self._email_result(spf_policy="+all")}
        sig = extract_signals(results)
        assert any("+all" in w for w in sig["auto_warnings"])

    def test_email_missing_dkim_warning(self):
        results = {"email_security": self._email_result(dkim=False)}
        sig = extract_signals(results)
        assert any("DKIM" in w for w in sig["auto_warnings"])

    def test_email_dmarc_none_policy_warning(self):
        results = {"email_security": self._email_result(dmarc_policy="none")}
        sig = extract_signals(results)
        assert any("'none'" in w for w in sig["auto_warnings"])

    def test_email_missing_dmarc_warning(self):
        results = {"email_security": self._email_result(dmarc=False)}
        sig = extract_signals(results)
        assert any("DMARC missing" in w for w in sig["auto_warnings"])

    def test_email_failure_no_crash(self):
        sig = extract_signals({"email_security": {"success": False}})
        assert sig["email_security"] == {}

    # ── 3.10 CVE ───────────────────────────────────────────────────────────

    def _cve_result(self, cves: list) -> dict:
        return {"success": True, "cves": cves}

    def test_cve_critical_score_triggers_warning(self):
        results = {"cve": self._cve_result([{"id": "CVE-2024-0001", "cvss": 9.5, "summary": "RCE"}])}
        sig = extract_signals(results)
        assert any("CRITICAL CVEs" in w for w in sig["auto_warnings"])

    def test_cve_high_score_triggers_warning(self):
        results = {"cve": self._cve_result([{"id": "CVE-2024-0002", "cvss": 7.8, "summary": "Privesc"}])}
        sig = extract_signals(results)
        assert any("High-severity" in w for w in sig["auto_warnings"])

    def test_cve_low_score_no_warning(self):
        results = {"cve": self._cve_result([{"id": "CVE-2024-0003", "cvss": 3.5, "summary": "Info"}])}
        sig = extract_signals(results)
        cve_warnings = [w for w in sig["auto_warnings"] if "CVE" in w]
        assert not cve_warnings

    def test_cve_alternate_key_names(self):
        results = {"cve": {"success": True, "cves": [{"cve_id": "CVE-2024-0004", "cvss_score": 9.1, "description": "RCE"}]}}
        sig = extract_signals(results)
        # cve_id / cvss_score / description are alternate keys
        assert len(sig["cves_found"]) == 1

    def test_cve_failure_no_crash(self):
        sig = extract_signals({"cve": {"success": False}})
        assert sig["cves_found"] == []

    # ── 3.11 IP REPUTATION ─────────────────────────────────────────────────

    def test_ip_reputation_flagged_stores_true(self):
        results = {"ip_reputation": {"success": True, "is_malicious": True, "score": 90, "categories": ["malware"]}}
        sig = extract_signals(results)
        assert sig["ip_reputation_flagged"] is True
        assert any("MALICIOUS" in w for w in sig["auto_warnings"])

    def test_ip_reputation_elevated_score_warning(self):
        results = {"ip_reputation": {"success": True, "is_malicious": False, "score": 40, "categories": []}}
        sig = extract_signals(results)
        assert any("elevated risk" in w for w in sig["auto_warnings"])

    def test_ip_reputation_low_score_no_warning(self):
        results = {"ip_reputation": {"success": True, "is_malicious": False, "score": 5, "categories": []}}
        sig = extract_signals(results)
        ip_warnings = [w for w in sig["auto_warnings"] if "IP" in w or "reputation" in w.lower()]
        assert not ip_warnings

    def test_ip_reputation_non_numeric_score_no_crash(self):
        results = {"ip_reputation": {"success": True, "is_malicious": False, "score": "N/A", "categories": []}}
        sig = extract_signals(results)
        assert sig["ip_reputation_flagged"] is False

    def test_ip_reputation_failure_no_crash(self):
        sig = extract_signals({"ip_reputation": {"success": False}})
        assert sig["ip_reputation_flagged"] is False


# ===========================================================================
# 4.  ct_summary
# ===========================================================================

class TestCtSummary:

    @patch("tools.fullrecon_tool.cert_transparency")
    def test_returns_failure_on_cert_transparency_fail(self, mock_ct):
        mock_ct.return_value = {"success": False, "error": "timeout"}
        result = ct_summary("example.com")
        assert result["success"] is False

    @patch("tools.fullrecon_tool.cert_transparency")
    def test_caps_sample_subdomains_at_50(self, mock_ct):
        subdomains = [f"sub{i}.example.com" for i in range(200)]
        mock_ct.return_value = {
            "success":           True,
            "unique_subdomains": subdomains,
        }
        result = ct_summary("example.com")
        assert result["success"] is True
        assert len(result["sample_subdomains"]) == 50

    @patch("tools.fullrecon_tool.cert_transparency")
    def test_uses_total_unique_subdomains_field_if_present(self, mock_ct):
        mock_ct.return_value = {
            "success":                True,
            "total_unique_subdomains": 123,
            "unique_subdomains":       ["a.com"] * 10,
        }
        result = ct_summary("example.com")
        assert result["total_unique_subdomains"] == 123

    @patch("tools.fullrecon_tool.cert_transparency")
    def test_counts_from_list_when_total_missing(self, mock_ct):
        mock_ct.return_value = {
            "success":         True,
            "unique_subdomains": ["a.com", "b.com", "c.com"],
        }
        result = ct_summary("example.com")
        assert result["total_unique_subdomains"] == 3


# ===========================================================================
# 5.  _extract_ip
# ===========================================================================

class TestExtractIp:

    def test_prefers_asn_ip(self):
        results = {
            "asn": {"success": True, "ip": "1.2.3.4"},
            "dns": {"success": True, "records": {"A": ["9.9.9.9"]}},
        }
        assert _extract_ip(results, "example.com") == "1.2.3.4"

    def test_falls_back_to_dns_a_record(self):
        results = {
            "asn": {"success": False},
            "dns": {"success": True, "records": {"A": ["8.8.8.8"]}},
        }
        assert _extract_ip(results, "example.com") == "8.8.8.8"

    def test_returns_none_when_no_ip_available(self):
        results = {
            "asn": {"success": False},
            "dns": {"success": True, "records": {}},
        }
        assert _extract_ip(results, "example.com") is None

    def test_asn_nested_data_key(self):
        results = {
            "asn": {"success": True, "data": {"ip": "5.5.5.5"}},
        }
        assert _extract_ip(results, "example.com") == "5.5.5.5"

    def test_strips_whitespace_from_ip(self):
        results = {"asn": {"success": True, "ip": "  2.2.2.2  "}}
        assert _extract_ip(results, "example.com") == "2.2.2.2"

    def test_empty_results_returns_none(self):
        assert _extract_ip({}, "example.com") is None


# ===========================================================================
# 6.  _extract_software
# ===========================================================================

class TestExtractSoftware:

    def test_returns_server_from_techstack(self):
        results = {"techstack": {"success": True, "server": "Apache", "server_version": "2.4.51"}}
        sw, ver = _extract_software(results)
        assert sw == "Apache"
        assert ver == "2.4.51"

    def test_ignores_unknown_server(self):
        results = {
            "techstack": {"success": True, "server": "Unknown"},
            "ports":     {
                "success": True,
                "results": [
                    {"protocols": {"tcp": [{"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH_8"}]}}
                ],
            },
        }
        sw, ver = _extract_software(results)
        assert sw == "ssh"
        assert ver == "OpenSSH_8"

    def test_falls_back_to_ports_when_techstack_fails(self):
        results = {
            "techstack": {"success": False},
            "ports": {
                "success": True,
                "results": [
                    {"protocols": {"tcp": [{"port": 3306, "state": "open", "service": "mysql", "version": "5.7"}]}}
                ],
            },
        }
        sw, ver = _extract_software(results)
        assert sw == "mysql"

    def test_skips_closed_ports(self):
        results = {
            "techstack": {"success": False},
            "ports": {
                "success": True,
                "results": [
                    {"protocols": {"tcp": [{"port": 3306, "state": "closed", "service": "mysql", "version": ""}]}}
                ],
            },
        }
        sw, ver = _extract_software(results)
        assert sw == ""

    def test_skips_http_https_unknown_services_in_ports(self):
        results = {
            "techstack": {"success": False},
            "ports": {
                "success": True,
                "results": [
                    {"protocols": {"tcp": [
                        {"port": 80,  "state": "open", "service": "http",    "version": ""},
                        {"port": 443, "state": "open", "service": "https",   "version": ""},
                        {"port": 8080,"state": "open", "service": "unknown", "version": ""},
                    ]}}
                ],
            },
        }
        sw, ver = _extract_software(results)
        assert sw == ""

    def test_empty_results_returns_empty_strings(self):
        assert _extract_software({}) == ("", "")


# ===========================================================================
# 7.  full_recon (orchestration)
# ===========================================================================

TOOL_MODULES = {
    "whois_lookup":         "tools.fullrecon_tool.whois_lookup",
    "dns_enumeration":      "tools.fullrecon_tool.dns_enumeration",
    "port_scan":            "tools.fullrecon_tool.port_scan",
    "ssl_inspect":          "tools.fullrecon_tool.ssl_inspect",
    "tech_stack_detect":    "tools.fullrecon_tool.tech_stack_detect",
    "asn_lookup":           "tools.fullrecon_tool.asn_lookup",
    "cert_transparency":    "tools.fullrecon_tool.cert_transparency",
    "headers_analyzer":     "tools.fullrecon_tool.headers_analyzer",
    "email_security_check": "tools.fullrecon_tool.email_security_check",
    "cve_lookup":           "tools.fullrecon_tool.cve_lookup",
    "ip_reputation":        "tools.fullrecon_tool.ip_reputation",
    "is_valid_domain":      "tools.fullrecon_tool.is_valid_domain",
}

def _patch_all_tools(valid_domain=True, software="nginx", software_version="1.20", ip="1.2.3.4"):
    """
    Returns a list of mock patch objects that stub out ALL external tool calls
    so full_recon can run without any real network activity.
    """
    patches = {}

    patches["is_valid_domain"] = patch(
        TOOL_MODULES["is_valid_domain"], return_value=valid_domain
    )
    patches["whois_lookup"] = patch(
        TOOL_MODULES["whois_lookup"],
        return_value={"success": True, "expiration_date": _future_iso(365)},
    )
    patches["dns_enumeration"] = patch(
        TOOL_MODULES["dns_enumeration"],
        return_value={"success": True, "records": {"A": [ip], "MX": ["mail.example.com"]}},
    )
    patches["port_scan"] = patch(
        TOOL_MODULES["port_scan"],
        return_value={"success": True, "results": []},
    )
    patches["ssl_inspect"] = patch(
        TOOL_MODULES["ssl_inspect"],
        return_value={"success": True, "expires": _future_iso(90)},
    )
    patches["tech_stack_detect"] = patch(
        TOOL_MODULES["tech_stack_detect"],
        return_value={"success": True, "server": software, "server_version": software_version},
    )
    patches["asn_lookup"] = patch(
        TOOL_MODULES["asn_lookup"],
        return_value={"success": True, "ip": ip, "abuse_score": 0},
    )
    patches["cert_transparency"] = patch(
        TOOL_MODULES["cert_transparency"],
        return_value={"success": True, "unique_subdomains": ["a.example.com"], "total_unique_subdomains": 1},
    )
    patches["headers_analyzer"] = patch(
        TOOL_MODULES["headers_analyzer"],
        return_value={"success": True, "status_code": 200, "headers": {}},
    )
    patches["email_security_check"] = patch(
        TOOL_MODULES["email_security_check"],
        return_value={
            "success": True, "security_score": "100%", "rating": "Excellent",
            "spf":   {"found": True,  "policy": "-all"},
            "dkim":  {"found": True},
            "dmarc": {"found": True,  "policy": "reject"},
        },
    )
    patches["cve_lookup"] = patch(
        TOOL_MODULES["cve_lookup"],
        return_value={"success": True, "cves": []},
    )
    patches["ip_reputation"] = patch(
        TOOL_MODULES["ip_reputation"],
        return_value={"success": True, "is_malicious": False, "score": 0, "categories": []},
    )
    return patches


class TestFullRecon:

    def test_invalid_domain_returns_error(self):
        with patch(TOOL_MODULES["is_valid_domain"], return_value=False):
            result = full_recon("not-valid!!domain")
        assert result["success"] is False
        assert "Invalid domain" in result["error"]

    def test_valid_domain_returns_success(self):
        patches = _patch_all_tools()
        with (
            patches["is_valid_domain"],
            patches["whois_lookup"],
            patches["dns_enumeration"],
            patches["port_scan"],
            patches["ssl_inspect"],
            patches["tech_stack_detect"],
            patches["asn_lookup"],
            patches["cert_transparency"],
            patches["headers_analyzer"],
            patches["email_security_check"],
            patches["cve_lookup"],
            patches["ip_reputation"],
        ):
            result = full_recon("example.com")

        assert result["success"] is True
        assert result["domain"] == "example.com"

    def test_result_contains_all_expected_keys(self):
        patches = _patch_all_tools()
        with (
            patches["is_valid_domain"],
            patches["whois_lookup"],
            patches["dns_enumeration"],
            patches["port_scan"],
            patches["ssl_inspect"],
            patches["tech_stack_detect"],
            patches["asn_lookup"],
            patches["cert_transparency"],
            patches["headers_analyzer"],
            patches["email_security_check"],
            patches["cve_lookup"],
            patches["ip_reputation"],
        ):
            result = full_recon("example.com")

        for key in ["domain", "scanned_at", "mode", "tool_coverage", "tools_summary",
                    "raw_results", "pre_extracted_signals", "instructions"]:
            assert key in result, f"Missing key: {key}"

    def test_tool_coverage_audit_all_11_tools_present(self):
        patches = _patch_all_tools()
        with (
            patches["is_valid_domain"],
            patches["whois_lookup"],
            patches["dns_enumeration"],
            patches["port_scan"],
            patches["ssl_inspect"],
            patches["tech_stack_detect"],
            patches["asn_lookup"],
            patches["cert_transparency"],
            patches["headers_analyzer"],
            patches["email_security_check"],
            patches["cve_lookup"],
            patches["ip_reputation"],
        ):
            result = full_recon("example.com")

        coverage = result["tool_coverage"]
        expected_tools = {"whois", "dns", "ports", "ssl", "techstack",
                          "asn", "ct_logs", "headers", "email_security", "cve", "ip_reputation"}
        assert expected_tools == set(coverage.keys())

    def test_tools_summary_counts_correct(self):
        patches = _patch_all_tools()
        with (
            patches["is_valid_domain"],
            patches["whois_lookup"],
            patches["dns_enumeration"],
            patches["port_scan"],
            patches["ssl_inspect"],
            patches["tech_stack_detect"],
            patches["asn_lookup"],
            patches["cert_transparency"],
            patches["headers_analyzer"],
            patches["email_security_check"],
            patches["cve_lookup"],
            patches["ip_reputation"],
        ):
            result = full_recon("example.com")

        summary = result["tools_summary"]
        assert summary["total"] == 11
        assert summary["succeeded"] + summary["skipped"] + summary["failed"] <= 11

    def test_cve_skipped_when_no_software_detected(self):
        """When techstack returns no recognisable software, CVE lookup must be skipped."""
        patches = _patch_all_tools(software="Unknown", software_version="")
        # Override techstack to return an unusable server name
        patches["tech_stack_detect"] = patch(
            TOOL_MODULES["tech_stack_detect"],
            return_value={"success": True, "server": "Unknown"},
        )
        with (
            patches["is_valid_domain"],
            patches["whois_lookup"],
            patches["dns_enumeration"],
            patches["port_scan"],
            patches["ssl_inspect"],
            patches["tech_stack_detect"],
            patches["asn_lookup"],
            patches["cert_transparency"],
            patches["headers_analyzer"],
            patches["email_security_check"],
            patches["cve_lookup"],
            patches["ip_reputation"],
        ):
            result = full_recon("example.com")

        cve_status = result["tool_coverage"].get("cve", "")
        assert "skipped" in cve_status

    def test_ip_reputation_skipped_when_no_ip(self):
        """When neither ASN nor DNS returns an IP, ip_reputation must be skipped."""
        patches = _patch_all_tools()
        patches["asn_lookup"] = patch(
            TOOL_MODULES["asn_lookup"],
            return_value={"success": False},
        )
        patches["dns_enumeration"] = patch(
            TOOL_MODULES["dns_enumeration"],
            return_value={"success": True, "records": {}},  # no A record
        )
        with (
            patches["is_valid_domain"],
            patches["whois_lookup"],
            patches["dns_enumeration"],
            patches["port_scan"],
            patches["ssl_inspect"],
            patches["tech_stack_detect"],
            patches["asn_lookup"],
            patches["cert_transparency"],
            patches["headers_analyzer"],
            patches["email_security_check"],
            patches["cve_lookup"],
            patches["ip_reputation"],
        ):
            result = full_recon("example.com")

        ip_status = result["tool_coverage"].get("ip_reputation", "")
        assert "skipped" in ip_status

    def test_tool_exception_captured_as_failed(self):
        """If a tool raises an exception it must appear as 'failed' in coverage."""
        patches = _patch_all_tools()
        patches["whois_lookup"] = patch(
            TOOL_MODULES["whois_lookup"],
            side_effect=RuntimeError("network timeout"),
        )
        with (
            patches["is_valid_domain"],
            patches["whois_lookup"],
            patches["dns_enumeration"],
            patches["port_scan"],
            patches["ssl_inspect"],
            patches["tech_stack_detect"],
            patches["asn_lookup"],
            patches["cert_transparency"],
            patches["headers_analyzer"],
            patches["email_security_check"],
            patches["cve_lookup"],
            patches["ip_reputation"],
        ):
            result = full_recon("example.com")

        assert result["success"] is True  # overall recon still succeeds
        assert result["tool_coverage"]["whois"].startswith("failed")

    def test_instructions_contain_domain(self):
        patches = _patch_all_tools()
        with (
            patches["is_valid_domain"],
            patches["whois_lookup"],
            patches["dns_enumeration"],
            patches["port_scan"],
            patches["ssl_inspect"],
            patches["tech_stack_detect"],
            patches["asn_lookup"],
            patches["cert_transparency"],
            patches["headers_analyzer"],
            patches["email_security_check"],
            patches["cve_lookup"],
            patches["ip_reputation"],
        ):
            result = full_recon("example.com")

        assert "example.com" in result["instructions"]

    def test_scanned_at_is_utc_iso_format(self):
        patches = _patch_all_tools()
        with (
            patches["is_valid_domain"],
            patches["whois_lookup"],
            patches["dns_enumeration"],
            patches["port_scan"],
            patches["ssl_inspect"],
            patches["tech_stack_detect"],
            patches["asn_lookup"],
            patches["cert_transparency"],
            patches["headers_analyzer"],
            patches["email_security_check"],
            patches["cve_lookup"],
            patches["ip_reputation"],
        ):
            result = full_recon("example.com")

        scanned_at = result["scanned_at"]
        assert scanned_at.endswith("Z"), f"Expected UTC 'Z' suffix, got: {scanned_at}"

    def test_mode_is_threat_analysis(self):
        patches = _patch_all_tools()
        with (
            patches["is_valid_domain"],
            patches["whois_lookup"],
            patches["dns_enumeration"],
            patches["port_scan"],
            patches["ssl_inspect"],
            patches["tech_stack_detect"],
            patches["asn_lookup"],
            patches["cert_transparency"],
            patches["headers_analyzer"],
            patches["email_security_check"],
            patches["cve_lookup"],
            patches["ip_reputation"],
        ):
            result = full_recon("example.com")

        assert result["mode"] == "threat_analysis"


# ===========================================================================
# 8.  THREAT_ANALYSIS_PROMPT (smoke test)
# ===========================================================================

class TestThreatAnalysisPrompt:

    def test_prompt_contains_placeholder_domain(self):
        assert "{domain}" in THREAT_ANALYSIS_PROMPT

    def test_prompt_contains_placeholder_scanned_at(self):
        assert "{scanned_at}" in THREAT_ANALYSIS_PROMPT

    def test_prompt_contains_placeholder_signals_block(self):
        assert "{signals_block}" in THREAT_ANALYSIS_PROMPT

    def test_prompt_formats_cleanly(self):
        filled = THREAT_ANALYSIS_PROMPT.format(
            domain="test.com",
            scanned_at="2026-01-01T00:00:00Z",
            signals_block="test signal",
        )
        assert "test.com" in filled
        assert "test signal" in filled