"""Regression tests for ASN signal extraction (issue #117)."""
from tools.signals.asn import asn_extractor
from tools.signals.extractor import extract_signals


def _signals():
    return {
        "domain_expiry_days": None,
        "dns_missing_records": [],
        "open_ports": [],
        "ssl_days_remaining": None,
        "software_detected": [],
        "ip_abuse_score": 0,
        "subdomain_count": 0,
        "missing_security_headers": [],
        "email_security": {},
        "ip_reputation_flagged": False,
        "asn_number": None,
        "asn_org": None,
        "asn_isp": None,
        "asn_country": None,
        "auto_warnings": [],
    }


def test_asn_extractor_success_populates_fields():
    result = {
        "success": True,
        "ip": "8.8.8.8",
        "asn": "AS15169",
        "organization": "GOOGLE",
        "country": "US",
        "bgp_prefix": "8.8.8.0/24",
        "registry": "arin",
        "allocated": "2023-12-28",
    }
    signals = _signals()
    asn_extractor(result, signals)
    assert signals["asn_number"] == "AS15169"
    assert signals["asn_org"] == "GOOGLE"
    assert signals["asn_isp"] == "GOOGLE"
    assert signals["asn_country"] == "US"


def test_asn_extractor_failure_is_noop():
    signals = _signals()
    before = dict(signals)
    asn_extractor({"success": False, "error": "timeout"}, signals)
    assert signals == before


def test_extract_signals_includes_asn_fields():
    results = {
        "whois": {"success": False},
        "dns": {"success": False},
        "ssl": {"success": False},
        "email_security": {"success": False},
        "asn": {
            "success": True,
            "ip": "1.1.1.1",
            "asn": "AS13335",
            "organization": "CLOUDFLARENET",
            "country": "US",
        },
        "ports": {"success": False},
        "techstack": {"success": False},
        "ct_logs": {"success": False},
        "ip_reputation": {"success": False},
    }
    signals = extract_signals(results)
    assert signals["asn_number"] == "AS13335"
    assert signals["asn_org"] == "CLOUDFLARENET"
    assert signals["asn_isp"] == "CLOUDFLARENET"
    assert signals["asn_country"] == "US"
    assert signals["ip_abuse_score"] == 0
