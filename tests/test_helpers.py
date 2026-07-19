from utils.helpers import is_valid_domain, normalize_domain, get_cvss_details, get_english_description, safe_parse_datetime
from datetime import datetime, timezone
import unittest

class TestHelpers(unittest.TestCase):

    # ── is_valid_domain ──────────────────────────────────────
    def test_valid_domains(self):
        for d in ["example.com", "sub.example.com", "a.b.c.org", "xn--nxasmq6b.com"]:
            with self.subTest(domain=d):
                self.assertTrue(is_valid_domain(d))

    def test_invalid_domains(self):
        for d in ["", "localhost", "192.168.1.1", "no-tld", "bad domain.com", "-start.com"]:
            with self.subTest(domain=d):
                self.assertFalse(is_valid_domain(d))


    # ── normalize_domain ─────────────────────────────────────
    def test_normalize_domain_strips_and_lowercases(self):
        self.assertEqual(normalize_domain("  Google.COM  "), "google.com")

    def test_normalize_domain_removes_trailing_dot(self):
        self.assertEqual(normalize_domain("google.com."), "google.com")

    def test_normalize_domain_empty_after_strip(self):
        self.assertEqual(normalize_domain("   "), "")
        self.assertEqual(normalize_domain(None), "")

    def test_normalize_domain_then_validates(self):
        self.assertTrue(is_valid_domain(normalize_domain("Google.COM")))
        self.assertTrue(is_valid_domain(normalize_domain("google.com.")))
    # ── get_cvss_details ─────────────────────────────────────
    def test_cvss_v31_extraction(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [
                    {"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}
                ]
            }
        }
        result = get_cvss_details(cve)
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["score"], 7.5)

    def test_cvss_falls_back_to_v2(self):
        cve = {
            "metrics": {
                "cvssMetricV2": [
                    {"baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}
                ]
            }
        }
        result = get_cvss_details(cve)
        self.assertEqual(result["severity"], "MEDIUM")

    def test_cvss_no_metrics_returns_unknown(self):
        result = get_cvss_details({})
        self.assertEqual(result["severity"], "Unknown")
        self.assertIsNone(result["score"])

    # ── get_english_description ──────────────────────────────
    def test_english_description_extracted(self):
        cve = {"descriptions": [{"lang": "fr", "value": "Bonjour"}, {"lang": "en", "value": "Hello"}]}
        self.assertEqual(get_english_description(cve), "Hello")

    def test_no_english_description_returns_empty(self):
        cve = {"descriptions": [{"lang": "fr", "value": "Bonjour"}]}
        self.assertEqual(get_english_description(cve), "")

    def test_empty_descriptions_returns_empty(self):
        self.assertEqual(get_english_description({}), "")

    # ── safe_parse_datetime ─────────────────────────────────

    def test_safe_parse_datetime_iso_string(self):
        """A standard ISO datetime string parses correctly."""
        result = safe_parse_datetime("2025-12-25 00:00:00")
        self.assertEqual(result, datetime(2025, 12, 25, 0, 0, 0))

    def test_safe_parse_datetime_none_input(self):
        """None or empty input returns None."""
        self.assertIsNone(safe_parse_datetime(None))
        self.assertIsNone(safe_parse_datetime(""))
        self.assertIsNone(safe_parse_datetime([]))

    def test_safe_parse_datetime_passthrough_datetime_object(self):
        """A datetime object is returned as-is."""
        dt = datetime(2025, 12, 25, 0, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(safe_parse_datetime(dt), dt)

    def test_safe_parse_datetime_list_takes_first_element(self):
        """A list of date strings (python-whois TLD variance) takes the first.

        Regression test for the bug where str(list) produced
        "['2025-12-25 00:00:00']" which matched no format, silently
        suppressing domain-expiry warnings in whois_extractor.
        """
        result = safe_parse_datetime(["2025-12-25 00:00:00", "2026-01-01 00:00:00"])
        self.assertEqual(result, datetime(2025, 12, 25, 0, 0, 0))

    def test_safe_parse_datetime_list_of_datetime_objects(self):
        """A list of datetime objects takes the first element as-is."""
        dt1 = datetime(2025, 12, 25, 0, 0, 0, tzinfo=timezone.utc)
        dt2 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(safe_parse_datetime([dt1, dt2]), dt1)

    def test_safe_parse_datetime_empty_list_returns_none(self):
        """An empty list returns None, not a crash."""
        self.assertIsNone(safe_parse_datetime([]))

    def test_safe_parse_datetime_list_with_empty_first_element(self):
        """A list whose first element is empty/None falls through to None."""
        self.assertIsNone(safe_parse_datetime([None, "2025-12-25"]))
        self.assertIsNone(safe_parse_datetime(["", "2025-12-25"]))

    def test_safe_parse_datetime_invalid_string_returns_none(self):
        """A genuinely unparseable string returns None, not a crash."""
        self.assertIsNone(safe_parse_datetime("not-a-date"))

if __name__ == "__main__":
    unittest.main(verbosity=2)
