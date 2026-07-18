import socket
import unittest
from unittest.mock import MagicMock, patch

from tools.asn_tool import asn_lookup


# Sample Team Cymru WHOIS response for 8.8.8.8
CYMRU_RESPONSE_8_8_8_8 = (
    "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"
    "15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 1992-12-01 | GOOGLE, US\n"
)

# Sample Team Cymru WHOIS response for Cloudflare IPv6 DNS
CYMRU_RESPONSE_CLOUDFLARE_V6 = (
    "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"
    "13335   | 2606:4700:4700::1111 | 2606:4700::/32  | US | arin     | 2010-07-14 | CLOUDFLARENET, US\n"
)


def _make_fake_socket(response_text: str) -> MagicMock:
    """Build a fake socket that yields the given WHOIS response then closes."""
    fake_sock = MagicMock()
    response_bytes = response_text.encode("utf-8")
    if response_bytes:
        fake_sock.recv.side_effect = [response_bytes, b""]
    else:
        fake_sock.recv.side_effect = [b""]
    fake_sock.__enter__.return_value = fake_sock
    fake_sock.__exit__.return_value = None
    return fake_sock


class TestAsnLookup(unittest.TestCase):

    @patch("tools.asn_tool.socket.create_connection")
    def test_valid_ipv4_returns_asn_data(self, mock_create_connection):
        mock_create_connection.return_value = _make_fake_socket(CYMRU_RESPONSE_8_8_8_8)

        result = asn_lookup("8.8.8.8")

        self.assertTrue(result["success"])
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["asn"], "AS15169")
        self.assertEqual(result["country"], "US")
        self.assertIn("GOOGLE", result["organization"])
        self.assertEqual(result["bgp_prefix"], "8.8.8.0/24")
        self.assertEqual(result["registry"], "arin")
        self.assertEqual(result["allocated"], "1992-12-01")
        mock_create_connection.assert_called_once()

    @patch("tools.asn_tool.socket.create_connection")
    @patch("tools.asn_tool.socket.getaddrinfo")
    def test_valid_domain_returns_asn_data(self, mock_getaddrinfo, mock_create_connection):
        mock_getaddrinfo.return_value = [(None, None, None, None, ("8.8.8.8", 0))]
        mock_create_connection.return_value = _make_fake_socket(CYMRU_RESPONSE_8_8_8_8)

        result = asn_lookup("google.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["asn"], "AS15169")
        self.assertIn("GOOGLE", result["organization"])
        mock_getaddrinfo.assert_called_once()

    @patch("tools.asn_tool.socket.create_connection")
    @patch("tools.asn_tool.socket.getaddrinfo")
    def test_url_input_extracts_host(self, mock_getaddrinfo, mock_create_connection):
        mock_getaddrinfo.return_value = [(None, None, None, None, ("8.8.8.8", 0))]
        mock_create_connection.return_value = _make_fake_socket(CYMRU_RESPONSE_8_8_8_8)

        result = asn_lookup("https://google.com:443")

        self.assertTrue(result["success"])
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["asn"], "AS15169")
        # Verify getaddrinfo was called with the host, not the URL
        called_arg = mock_getaddrinfo.call_args[0][0]
        self.assertEqual(called_arg, "google.com")

    @patch("tools.asn_tool.socket.create_connection")
    def test_valid_ipv6_returns_asn_data(self, mock_create_connection):
        mock_create_connection.return_value = _make_fake_socket(CYMRU_RESPONSE_CLOUDFLARE_V6)

        result = asn_lookup("2606:4700:4700::1111")

        self.assertTrue(result["success"])
        self.assertEqual(result["ip"], "2606:4700:4700::1111")
        self.assertEqual(result["asn"], "AS13335")
        self.assertEqual(result["country"], "US")
        self.assertIn("CLOUDFLARE", result["organization"])

    @patch("tools.asn_tool.socket.getaddrinfo")
    def test_unresolvable_domain_returns_error(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")

        result = asn_lookup("thisdomaindoesnotexist.invalid")

        self.assertFalse(result["success"])
        self.assertIn("resolve", result["error"])

    @patch("tools.asn_tool.socket.create_connection")
    def test_whois_timeout_returns_error(self, mock_create_connection):
        mock_create_connection.side_effect = socket.timeout("timed out")

        result = asn_lookup("8.8.8.8")

        self.assertFalse(result["success"])
        self.assertIn("timed out", result["error"])

    @patch("tools.asn_tool.socket.create_connection")
    def test_connection_refused_returns_error(self, mock_create_connection):
        mock_create_connection.side_effect = ConnectionError("Connection refused")

        result = asn_lookup("8.8.8.8")

        self.assertFalse(result["success"])
        self.assertIn("Could not connect to Team Cymru WHOIS", result["error"])

    @patch("tools.asn_tool.socket.create_connection")
    def test_malformed_response_returns_error(self, mock_create_connection):
        # Empty response from the WHOIS service
        mock_create_connection.return_value = _make_fake_socket("")

        result = asn_lookup("8.8.8.8")

        self.assertFalse(result["success"])
        self.assertIn("malformed", result["error"])

    @patch("tools.asn_tool.socket.create_connection")
    def test_header_only_response_returns_error(self, mock_create_connection):
        # Response with only a header line and no data lines should be rejected.
        header_only = (
            "AS      | IP               | BGP Prefix          | CC | Registry | "
            "Allocated  | AS Name\n"
        )
        mock_create_connection.return_value = _make_fake_socket(header_only)

        result = asn_lookup("8.8.8.8")

        self.assertFalse(result["success"])
        self.assertIn("malformed", result["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
