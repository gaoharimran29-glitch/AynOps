from unittest.mock import MagicMock, patch
import socket
import unittest
from tools.whois_tool import whois_lookup

class TestWhoisLookup(unittest.TestCase):

    def _mock_whois_result(self):
        m = MagicMock()
        m.registrar = "Example Registrar LLC"
        m.whois_server = "whois.example.com"
        m.creation_date = "2010-01-01"
        m.expiration_date = "2030-01-01"
        m.updated_date = "2023-06-15"
        m.name_servers = ["ns1.example.com", "ns2.example.com"]
        m.status = "clientTransferProhibited"
        m.emails = "admin@example.com"
        m.dnssec = "unsigned"
        m.country = "US"
        m.org = "Example Org"
        return m

    @patch("tools.whois_tool.whois.whois")
    def test_whois_success(self, mock_whois):
        mock_whois.return_value = self._mock_whois_result()
        result = whois_lookup("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["registrar"], "Example Registrar LLC")
        self.assertEqual(result["country"], "US")
        self.assertEqual(result["org"], "Example Org")

    @patch("tools.whois_tool.whois.whois")
    def test_whois_list_dates_normalized(self, mock_whois):
        m = self._mock_whois_result()
        m.creation_date = ["2010-01-01", "2010-01-02"]  # some registrars return lists
        mock_whois.return_value = m
        result = whois_lookup("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["creation_date"], "2010-01-01")  # first item taken

    def test_whois_invalid_domain(self):
        result = whois_lookup("not-a-domain")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    @patch("tools.whois_tool.whois.whois", side_effect=Exception("WHOIS server timeout"))
    def test_whois_exception_caught(self, _):
        result = whois_lookup("example.com")
        self.assertFalse(result["success"])
        self.assertIn("WHOIS server timeout", result["error"])

    @patch("tools.whois_tool.whois.whois", side_effect=TimeoutError("WHOIS lookup timed out"))
    def test_whois_timeout_error_caught(self, _):
        result = whois_lookup("example.com")
        self.assertFalse(result["success"])
        self.assertIn("timed out after", result["error"])
        self.assertIn("10 seconds", result["error"])

    @patch("tools.whois_tool.whois.whois", side_effect=socket.timeout("connection timed out"))
    def test_whois_socket_timeout_caught(self, _):
        result = whois_lookup("example.com")
        self.assertFalse(result["success"])
        self.assertIn("timed out after", result["error"])
        self.assertIn("10 seconds", result["error"])

    @patch("tools.whois_tool.whois.whois")
    def test_whois_none_dates_return_null(self, mock_whois):
        m = self._mock_whois_result()
        m.expiration_date = None
        m.creation_date = None
        mock_whois.return_value = m
        result = whois_lookup("example.com")
        self.assertTrue(result["success"])
        self.assertIsNone(result["expiration_date"])
        self.assertIsNone(result["creation_date"])

if __name__ == "__main__":
    unittest.main(verbosity=2)