import unittest
from unittest.mock import patch, MagicMock
import urllib.error
from tools.headers_tool import headers_analyzer


class TestHeadersAnalyzer(unittest.TestCase):

    def _make_response(self, headers: dict, final_url: str = "https://example.com/"):
        """Helper to build a mock HTTP response."""
        mock_resp = MagicMock()
        mock_resp.headers = MagicMock()
        mock_resp.headers.items.return_value = list(headers.items())
        mock_resp.url = final_url
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    # ------------------------------------------------------------------
    # Domain validation
    # ------------------------------------------------------------------

    def test_invalid_domain_rejected(self):
        result = headers_analyzer("not-a-domain")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Invalid domain format")

    def test_ip_address_rejected(self):
        result = headers_analyzer("192.168.1.1")
        self.assertFalse(result["success"])

    # ------------------------------------------------------------------
    # Successful response
    # ------------------------------------------------------------------

    @patch("tools.headers_tool.urllib.request.OpenerDirector.open")
    def test_success_returns_correct_structure(self, mock_open):
        mock_open.return_value = self._make_response({
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        })
        result = headers_analyzer("example.com")
        self.assertTrue(result["success"])
        self.assertIn("domain", result)
        self.assertIn("headers", result)

    @patch("tools.headers_tool.urllib.request.OpenerDirector.open")
    def test_hsts_present_and_valid(self, mock_open):
        mock_open.return_value = self._make_response({
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertTrue(hsts["present"])
        self.assertEqual(hsts["issue"], "None")
        self.assertEqual(hsts["severity"], "low")

    @patch("tools.headers_tool.urllib.request.OpenerDirector.open")
    def test_hsts_missing_flagged_as_high(self, mock_open):
        mock_open.return_value = self._make_response({})
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertFalse(hsts["present"])
        self.assertEqual(hsts["severity"], "high")

    @patch("tools.headers_tool.urllib.request.OpenerDirector.open")
    def test_hsts_low_max_age_flagged(self, mock_open):
        mock_open.return_value = self._make_response({
            "Strict-Transport-Security": "max-age=3600",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertTrue(hsts["present"])
        self.assertIn("max-age", hsts["issue"])
        self.assertEqual(hsts["severity"], "medium")

    @patch("tools.headers_tool.urllib.request.OpenerDirector.open")
    def test_csp_missing_flagged(self, mock_open):
        mock_open.return_value = self._make_response({})
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertFalse(csp["present"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.urllib.request.OpenerDirector.open")
    def test_csp_unsafe_inline_flagged(self, mock_open):
        mock_open.return_value = self._make_response({
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertTrue(csp["present"])
        self.assertIn("unsafe-inline", csp["issue"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.urllib.request.OpenerDirector.open")
    def test_csp_report_only_mode_detected(self, mock_open):
        mock_open.return_value = self._make_response({
            "Content-Security-Policy-Report-Only": "default-src 'self'",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertTrue(csp["present"])
        self.assertIn("report-only mode", csp["issue"])
        self.assertEqual(csp["severity"], "medium")

    @patch("tools.headers_tool.urllib.request.OpenerDirector.open")
    def test_x_frame_options_deny_accepted(self, mock_open):
        mock_open.return_value = self._make_response({
            "X-Frame-Options": "DENY",
        })
        result = headers_analyzer("example.com")
        xfo = result["headers"]["x-frame-options"]
        self.assertTrue(xfo["present"])
        self.assertEqual(xfo["issue"], "None")

    @patch("tools.headers_tool.urllib.request.OpenerDirector.open")
    def test_x_content_type_options_nosniff_accepted(self, mock_open):
        mock_open.return_value = self._make_response({
            "X-Content-Type-Options": "nosniff",
        })
        result = headers_analyzer("example.com")
        xcto = result["headers"]["x-content-type-options"]
        self.assertTrue(xcto["present"])
        self.assertEqual(xcto["issue"], "None")

    @patch("tools.headers_tool.urllib.request.OpenerDirector.open")
    def test_server_header_flagged_as_disclosure(self, mock_open):
        mock_open.return_value = self._make_response({
            "Server": "Apache/2.4.41",
        })
        result = headers_analyzer("example.com")
        self.assertIn("server", result["headers"])
        self.assertIn("exposes technology", result["headers"]["server"]["issue"])

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    @patch("tools.headers_tool.urllib.request.OpenerDirector.open",
           side_effect=urllib.error.URLError("Connection refused"))
    def test_connection_error_returns_failure(self, _):
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("Connection failed", result["error"])

    @patch("tools.headers_tool.urllib.request.OpenerDirector.open",
           side_effect=Exception("Unexpected error"))
    def test_unexpected_exception_returns_failure(self, _):
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)