from unittest.mock import patch
import unittest
from tools.fullrecon_tool import full_recon

class TestFullRecon(unittest.TestCase):

    def test_invalid_domain_rejected(self):
        result = full_recon("not-a-domain")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    @patch("tools.fullrecon_tool.headers_analyzer", return_value={"success": True, "domain": "example.com", "headers": {}})
    @patch("tools.fullrecon_tool.whois_lookup", return_value={"success": True, "domain": "example.com"})
    @patch("tools.fullrecon_tool.dns_enumeration", return_value={"success": True, "records": {}})
    @patch("tools.fullrecon_tool.port_scan", return_value={"success": True, "results": []})
    @patch("tools.fullrecon_tool.ssl_inspect", return_value={"success": True, "certificate": {}})
    @patch("tools.fullrecon_tool.tech_stack_detect", return_value={"success": True, "technologies": {}})
    @patch("tools.fullrecon_tool.asn_lookup", return_value={"success": True, "asn": "AS12345"})
    @patch("tools.fullrecon_tool.ct_summary", return_value={"success": True, "total_unique_subdomains": 10, "sample_subdomains": ["api.example.com"]})
    def test_full_recon_calls_all_tools(self, mock_ct, mock_asn, mock_tech, mock_ssl, mock_ports, mock_dns, mock_whois, mock_headers):
        result = full_recon("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["domain"], "example.com")
        self.assertIn("scanned_at", result)
        self.assertIn("results", result)

        # All 5 subtool results present
        self.assertIn("whois", result["results"])
        self.assertIn("dns", result["results"])
        self.assertIn("ports", result["results"])
        self.assertIn("ssl", result["results"])
        self.assertIn("techstack", result["results"])
        self.assertIn("asn", result["results"])
        self.assertIn("ct_logs", result["results"])
        self.assertIn("headers", result["results"])
        mock_whois.assert_called_once_with("example.com")
        mock_dns.assert_called_once_with("example.com")
        mock_ssl.assert_called_once_with("example.com")
        mock_tech.assert_called_once_with("example.com")
        mock_ports.assert_called_once_with("example.com", "service")
        mock_asn.assert_called_once_with("example.com")
        mock_ct.assert_called_once_with("example.com")
        mock_headers.assert_called_once_with("example.com")

    @patch("tools.fullrecon_tool.whois_lookup", side_effect=Exception("WHOIS exploded"))
    @patch("tools.fullrecon_tool.dns_enumeration", return_value={"success": True})
    @patch("tools.fullrecon_tool.port_scan", return_value={"success": True})
    @patch("tools.fullrecon_tool.ssl_inspect", return_value={"success": True})
    @patch("tools.fullrecon_tool.tech_stack_detect", return_value={"success": True})
    @patch("tools.fullrecon_tool.asn_lookup", return_value={"success": True})
    @patch("tools.fullrecon_tool.ct_summary", return_value={"success": True})
    @patch("tools.fullrecon_tool.headers_analyzer", return_value={"success": True})
    def test_full_recon_tool_failure_isolated(self, mock_headers, mock_ct, mock_asn, mock_tech, mock_ssl, mock_ports, mock_dns, mock_whois):
        """One tool crashing must not crash the whole recon."""
        result = full_recon("example.com")

        self.assertTrue(result["success"])
        # The failing tool should have an error, others should be fine
        self.assertFalse(result["results"]["whois"]["success"])
        self.assertTrue(result["results"]["dns"]["success"])
        self.assertTrue(result["results"]["asn"]["success"])
        self.assertTrue(result["results"]["ct_logs"]["success"])

    @patch("tools.fullrecon_tool.whois_lookup", return_value={"success": True})
    @patch("tools.fullrecon_tool.dns_enumeration", return_value={"success": True})
    @patch("tools.fullrecon_tool.port_scan", return_value={"success": True})
    @patch("tools.fullrecon_tool.ssl_inspect", return_value={"success": True})
    @patch("tools.fullrecon_tool.tech_stack_detect", return_value={"success": True})
    @patch("tools.fullrecon_tool.asn_lookup", return_value={"success": True})
    @patch("tools.fullrecon_tool.ct_summary", return_value={"success": True})
    @patch("tools.fullrecon_tool.headers_analyzer", return_value={"success": True})
    def test_full_recon_scanned_at_is_iso_format(self, mock_headers, mock_ct, mock_asn, mock_tech, mock_ssl, mock_ports, mock_dns, mock_whois):
        from datetime import datetime
        result = full_recon("example.com")
        # Should be parseable ISO timestamp ending in Z
        ts = result["scanned_at"]
        self.assertTrue(ts.endswith("Z"))
        datetime.fromisoformat(ts.rstrip("Z"))  # raises if invalid


if __name__ == "__main__":
    unittest.main(verbosity=2)