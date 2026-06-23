import unittest
from unittest.mock import patch, MagicMock
import dns.resolver
from tools.email_security_tool import email_security_check

def _txt_answer(text: str):
    record = MagicMock()
    record.strings = [text.encode("utf-8")]
    return [record]

class TestEmailSecurityCheck(unittest.TestCase):

    def test_invalid_domain(self):
        result = email_security_check("not a domain")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_matches_issue_worked_example(self, mock_resolve):
        def fake_resolve(name, rtype, lifetime=5):
            if name == "example.com":
                return _txt_answer("v=spf1 include:_spf.google.com ~all")
            if name == "_dmarc.example.com":
                return _txt_answer("v=DMARC1; p=reject;")
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = fake_resolve

        result = email_security_check("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["spf"]["found"], True)
        self.assertEqual(result["spf"]["policy"], "softfail")
        self.assertEqual(result["dmarc"]["found"], True)
        self.assertEqual(result["dmarc"]["policy"], "reject")
        self.assertEqual(result["dkim"]["found"], False)
        self.assertEqual(result["security_score"], "66%")
        self.assertEqual(result["rating"], "Fair")
        self.assertTrue(
            any("DKIM not found" in r for r in result["recommendations"])
        )

    # ── SPF ──────────────────────────────────────────────────────

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_spf_missing(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        result = email_security_check("example.com")

        self.assertFalse(result["spf"]["found"])
        self.assertIsNone(result["spf"]["record"])
        self.assertIsNone(result["spf"]["policy"])
        self.assertTrue(any("SPF not found" in r for r in result["recommendations"]))

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_spf_hard_fail_no_negative_recommendation(self, mock_resolve):
        def fake_resolve(name, rtype, lifetime=5):
            if name == "example.com":
                return _txt_answer("v=spf1 include:_spf.google.com -all")
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = fake_resolve

        result = email_security_check("example.com")

        self.assertTrue(result["spf"]["found"])
        self.assertEqual(result["spf"]["policy"], "fail")
        spf_negative_phrases = ("softfail", "Multiple SPF", "little real protection", "no clear terminal")
        self.assertFalse(
            any(phrase in r for r in result["recommendations"] for phrase in spf_negative_phrases)
        )

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_spf_multiple_records_flagged(self, mock_resolve):
        def fake_resolve(name, rtype, lifetime=5):
            if name == "example.com":
                r1 = MagicMock()
                r1.strings = [b"v=spf1 -all"]
                r2 = MagicMock()
                r2.strings = [b"v=spf1 include:_spf.google.com -all"]
                return [r1, r2]
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = fake_resolve

        result = email_security_check("example.com")

        self.assertTrue(result["spf"]["found"])
        self.assertTrue(any("Multiple SPF" in r for r in result["recommendations"]))

    # ── DMARC ────────────────────────────────────────────────────

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_dmarc_missing(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        result = email_security_check("example.com")

        self.assertFalse(result["dmarc"]["found"])
        self.assertTrue(any("DMARC not found" in r for r in result["recommendations"]))

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_dmarc_policy_none_flagged(self, mock_resolve):
        def fake_resolve(name, rtype, lifetime=5):
            if name == "_dmarc.example.com":
                return _txt_answer("v=DMARC1; p=none; rua=mailto:dmarc@example.com")
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = fake_resolve

        result = email_security_check("example.com")

        self.assertTrue(result["dmarc"]["found"])
        self.assertEqual(result["dmarc"]["policy"], "none")
        self.assertTrue(any("monitoring-only" in r for r in result["recommendations"]))

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_dmarc_reject_with_rua_is_clean(self, mock_resolve):
        def fake_resolve(name, rtype, lifetime=5):
            if name == "_dmarc.example.com":
                return _txt_answer("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = fake_resolve

        result = email_security_check("example.com")

        self.assertEqual(result["dmarc"]["policy"], "reject")
        self.assertFalse(any("DMARC" in r for r in result["recommendations"]))

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_dmarc_missing_rua_flagged(self, mock_resolve):
        def fake_resolve(name, rtype, lifetime=5):
            if name == "_dmarc.example.com":
                return _txt_answer("v=DMARC1; p=reject")
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = fake_resolve

        result = email_security_check("example.com")

        self.assertTrue(any("rua=" in r for r in result["recommendations"]))

    # ── DKIM ─────────────────────────────────────────────────────

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_dkim_selector_found(self, mock_resolve):
        def fake_resolve(name, rtype, lifetime=5):
            if name == "google._domainkey.example.com":
                return _txt_answer("v=DKIM1; k=rsa; p=MIGfMA0GCSq...")
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = fake_resolve

        result = email_security_check("example.com")

        self.assertTrue(result["dkim"]["found"])
        self.assertIn("google", result["dkim"]["selectors_checked"])

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_dkim_none_found(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        result = email_security_check("example.com")

        self.assertFalse(result["dkim"]["found"])

    # ── DNS timeout safety ───────────────────────────────────────

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_spf_timeout_flags_uncertainty_not_absence(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.LifetimeTimeout()

        result = email_security_check("example.com")

        self.assertFalse(result["spf"]["found"])
        self.assertTrue(
            any("Could not verify SPF" in r for r in result["recommendations"])
        )
        self.assertFalse(any("SPF not found" in r for r in result["recommendations"]))

    # ── Score / rating ───────────────────────────────────────────

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_score_100_when_all_three_found(self, mock_resolve):
        def fake_resolve(name, rtype, lifetime=5):
            if name == "example.com":
                return _txt_answer("v=spf1 -all")
            if name == "_dmarc.example.com":
                return _txt_answer("v=DMARC1; p=reject; rua=mailto:a@example.com")
            if name == "google._domainkey.example.com":
                return _txt_answer("v=DKIM1; k=rsa; p=MIGf...")
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = fake_resolve

        result = email_security_check("example.com")

        self.assertEqual(result["security_score"], "100%")
        self.assertEqual(result["rating"], "Excellent")

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_score_33_when_only_one_found(self, mock_resolve):
        def fake_resolve(name, rtype, lifetime=5):
            if name == "example.com":
                return _txt_answer("v=spf1 -all")
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = fake_resolve

        result = email_security_check("example.com")

        self.assertEqual(result["security_score"], "33%")
        self.assertEqual(result["rating"], "Poor")

    @patch("tools.email_security_tool.dns.resolver.resolve")
    def test_score_0_when_none_found(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        result = email_security_check("example.com")

        self.assertEqual(result["security_score"], "0%")
        self.assertEqual(result["rating"], "Critical")

if __name__ == "__main__":
    unittest.main(verbosity=2)