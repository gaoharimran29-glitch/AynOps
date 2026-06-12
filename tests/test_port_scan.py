import unittest
from unittest.mock import Mock, MagicMock, patch, call
from tools.portscan_tool import port_scan

class TestPortScan(unittest.TestCase):

    def _make_scanner_mock(self, host="93.184.216.34", open_ports=None):
        open_ports = open_ports or {80: {"state": "open", "name": "http", "product": "nginx", "version": "1.18"}}
        scanner = MagicMock()
        scanner.all_hosts.return_value = [host]
        scanner[host].hostname.return_value = "example.com"
        scanner[host].state.return_value = "up"
        scanner[host].all_protocols.return_value = ["tcp"]
        scanner[host]["tcp"].items.return_value = open_ports.items()
        return scanner

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_basic_scan_success(self, mock_cls):
        mock_cls.return_value = self._make_scanner_mock()
        result = port_scan("example.com", "basic")

        self.assertTrue(result["success"])
        self.assertEqual(result["target"], "example.com")
        self.assertEqual(result["scan_type"], "basic")
        self.assertEqual(result["hosts_found"], 1)
        self.assertIn("results", result)

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_scan_includes_port_details(self, mock_cls):
        mock_cls.return_value = self._make_scanner_mock()
        result = port_scan("example.com")

        port_entry = result["results"][0]["protocols"]["tcp"][0]
        self.assertEqual(port_entry["port"], 80)
        self.assertEqual(port_entry["service"], "http")
        self.assertEqual(port_entry["product"], "nginx")

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_scan_no_hosts_found(self, mock_cls):
        scanner = MagicMock()
        scanner.all_hosts.return_value = []
        mock_cls.return_value = scanner

        result = port_scan("192.0.2.1")
        self.assertTrue(result["success"])
        self.assertEqual(result["hosts_found"], 0)
        self.assertEqual(result["results"], [])

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_nmap_not_installed_error(self, mock_cls):
        import nmap
        mock_cls.return_value.scan.side_effect = nmap.PortScannerError("nmap not found")
        result = port_scan("example.com")

        self.assertFalse(result["success"])
        self.assertIn("Nmap not found", result["error"])

    @patch("tools.portscan_tool.nmap.PortScanner")
    def test_invalid_scan_type_returns_error(self, mock_cls):
        result = port_scan("example.com", scan_type="invalid_type")

        self.assertFalse(result["success"])
        self.assertIn("Invalid scan_type", result["error"])
        self.assertEqual(
            result["valid_scan_types"],
            ["basic", "service", "os", "full", "vuln"],
        )
        mock_cls.assert_not_called()

if __name__ == "__main__":
    unittest.main(verbosity=2)
