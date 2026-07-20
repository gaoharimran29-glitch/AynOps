"""Tests for the per-tool signal extractors in tools/signals/.

These tests pin down the contract that each extractor mutates the shared
`signals` dict in the way the threat-analysis prompt expects. They are
especially important for the ip_abuse_score signal, which was silently
always 0 between PR #84 and the fix that moved the assignment into
ip_reputation_extractor (the AbuseIPDB-backed canonical source).
"""
from tools.signals.asn import asn_extractor
from tools.signals.ip_reputation import ip_reputation_extractor
from tools.signals.extractor import extract_signals


def _base_signals():
    """Return a fresh signals dict matching extract_signals' initial shape."""
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


# ── ip_reputation_extractor ──────────────────────────────────────────────

def test_ip_reputation_extractor_populates_abuse_score():
    """ip_reputation_extractor must assign abuse_confidence_score to ip_abuse_score.

    Regression test for the bug introduced by PR #84: the signal was
    never assigned here, so it stayed at the initial value of 0 regardless
    of the real AbuseIPDB confidence score.
    """
    result = {
        "success": True,
        "is_malicious": False,
        "abuse_confidence_score": 87,
    }
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    assert signals["ip_abuse_score"] == 87
    assert signals["ip_reputation_flagged"] is False


def test_ip_reputation_extractor_coerces_string_score_to_int():
    """abuse_confidence_score may arrive as a string; the extractor must coerce."""
    result = {
        "success": True,
        "is_malicious": False,
        "abuse_confidence_score": "42",
    }
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    assert signals["ip_abuse_score"] == 42


def test_ip_reputation_extractor_defaults_score_to_zero_on_invalid_value():
    """A non-numeric abuse_confidence_score must fall back to 0."""
    result = {
        "success": True,
        "is_malicious": False,
        "abuse_confidence_score": "not-a-number",
    }
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    assert signals["ip_abuse_score"] == 0


def test_ip_reputation_extractor_defaults_score_to_zero_when_key_missing():
    """A missing abuse_confidence_score key must fall back to 0.

    AbuseIPDB responses normally include the field, but defensive coding
    requires the extractor to tolerate its absence (int(None) raises
    TypeError, which the try/except catches).
    """
    result = {
        "success": True,
        "is_malicious": False,
        # abuse_confidence_score intentionally omitted
    }
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    assert signals["ip_abuse_score"] == 0


def test_ip_reputation_extractor_skips_on_unsuccessful_result():
    """An unsuccessful ip_reputation result must not touch the signals dict."""
    result = {"success": False, "error": "AbuseIPDB API request failed"}
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    # ip_abuse_score stays at its initial value
    assert signals["ip_abuse_score"] == 0
    assert signals["ip_reputation_flagged"] is False
    assert signals["auto_warnings"] == []


def test_ip_reputation_extractor_flags_malicious_warning():
    """When is_malicious is True, a MALICIOUS warning must be appended."""
    result = {
        "success": True,
        "is_malicious": True,
        "abuse_confidence_score": 95,
    }
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    assert signals["ip_abuse_score"] == 95
    assert signals["ip_reputation_flagged"] is True
    assert any("MALICIOUS" in w for w in signals["auto_warnings"])


def test_ip_reputation_extractor_elevated_warning_above_20():
    """When not flagged but score > 20, an elevated-risk warning must fire."""
    result = {
        "success": True,
        "is_malicious": False,
        "abuse_confidence_score": 35,
    }
    signals = _base_signals()
    ip_reputation_extractor(result, signals)
    assert any("elevated risk" in w for w in signals["auto_warnings"])


# ── asn_extractor ────────────────────────────────────────────────────────

def test_asn_extractor_does_not_touch_ip_abuse_score():
    """asn_extractor must NOT zero out ip_abuse_score.

    The asn_tool result does not carry an abuse score. The previous
    implementation looked up `abuse_score` (which never existed) and fell
    back to 0, silently overwriting any value that had been or would be
    set by ip_reputation_extractor. This test locks in the fix: asn_extractor
    leaves ip_abuse_score untouched.
    """
    result = {
        "success": True,
        "ip": "1.2.3.4",
        "asn": "AS64500",
        "org": "Test Org",
        "isp": "Test ISP",
        "country": "Testland",
    }
    signals = _base_signals()
    signals["ip_abuse_score"] = 73  # pretend ip_reputation already ran
    asn_extractor(result, signals)
    assert signals["ip_abuse_score"] == 73  # unchanged


def test_asn_extractor_skips_on_unsuccessful_result():
    """An unsuccessful asn result must not touch the signals dict."""
    result = {"success": False, "error": "Failed to resolve domain"}
    signals = _base_signals()
    asn_extractor(result, signals)
    assert signals["ip_abuse_score"] == 0
    assert signals["auto_warnings"] == []


# ── extract_signals integration ──────────────────────────────────────────

def test_extract_signals_populates_ip_abuse_score_from_ip_reputation():
    """End-to-end: extract_signals must populate ip_abuse_score from the
    ip_reputation tool result, not from the asn tool result.

    This is the integration test that would have caught the original PR #84
    regression: asn runs in Wave 1, ip_reputation runs in Wave 3, and the
    extractor order follows the registry. Even though asn_extractor runs
    first, the final ip_abuse_score value must come from ip_reputation.
    """
    results = {
        "whois": {"success": False},
        "dns": {"success": False},
        "ssl": {"success": False},
        "email_security": {"success": False},
        "asn": {
            "success": True,
            "ip": "1.2.3.4",
            "asn": "AS64500",
            "org": "Test Org",
            "isp": "Test ISP",
            "country": "Testland",
        },
        "ports": {"success": False},
        "techstack": {"success": False},
        "ct_logs": {"success": False},
        "ip_reputation": {
            "success": True,
            "is_malicious": False,
            "abuse_confidence_score": 88,
        },
    }
    signals = extract_signals(results)
    assert signals["ip_abuse_score"] == 88
    assert signals["ip_reputation_flagged"] is False


def test_extract_signals_leaves_ip_abuse_score_at_zero_when_ip_reputation_missing():
    """When ip_reputation did not run or failed, ip_abuse_score stays at 0."""
    results = {
        "whois": {"success": False},
        "dns": {"success": False},
        "ssl": {"success": False},
        "email_security": {"success": False},
        "asn": {
            "success": True,
            "ip": "1.2.3.4",
            "asn": "AS64500",
            "org": "Test Org",
        },
        "ports": {"success": False},
        "techstack": {"success": False},
        "ct_logs": {"success": False},
        "ip_reputation": {"success": False, "error": "API down"},
    }
    signals = extract_signals(results)
    assert signals["ip_abuse_score"] == 0


def test_asn_extractor_populates_metadata_signals():
    """Successful ASN lookups must populate asn_* signal fields."""
    result = {
        "success": True,
        "ip": "1.2.3.4",
        "asn": "AS64500",
        "organization": "Example Networks",
        "isp": "Example ISP",
        "country": "US",
    }
    signals = _base_signals()
    asn_extractor(result, signals)
    assert signals["asn_number"] == "AS64500"
    assert signals["asn_org"] == "Example Networks"
    assert signals["asn_isp"] == "Example ISP"
    assert signals["asn_country"] == "US"
    assert signals["ip_abuse_score"] == 0


def test_asn_extractor_supports_legacy_org_field():
    """Legacy org field is accepted and also mirrored into asn_isp when isp missing."""
    result = {
        "success": True,
        "ip": "1.2.3.4",
        "asn": "AS64500",
        "org": "Legacy Org",
        "country": "DE",
    }
    signals = _base_signals()
    asn_extractor(result, signals)
    assert signals["asn_number"] == "AS64500"
    assert signals["asn_org"] == "Legacy Org"
    assert signals["asn_isp"] == "Legacy Org"
    assert signals["asn_country"] == "DE"


def test_asn_extractor_skips_metadata_on_failure():
    """Failed ASN lookups leave asn_* fields unset."""
    result = {"success": False, "error": "Failed to resolve domain"}
    signals = _base_signals()
    asn_extractor(result, signals)
    assert signals["asn_number"] is None
    assert signals["asn_org"] is None
    assert signals["asn_isp"] is None
    assert signals["asn_country"] is None

