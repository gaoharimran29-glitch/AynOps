import unittest
from unittest.mock import patch, Mock
import requests
from tools.redirect_tracer import trace_redirects


def _resp(status_code: int, headers: dict = None):
    m = Mock()
    m.status_code = status_code
    m.headers = headers or {}
    return m


class TestTraceRedirects(unittest.TestCase):

    # ------------------------------------------------------------------
    # Input validation / normalization
    # ------------------------------------------------------------------

    def test_invalid_domain_rejected(self):
        result = trace_redirects("not a domain")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Invalid domain format")

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_bare_domain_defaults_to_http(self, mock_get):
        """The whole point of this tool is checking whether HTTP gets
        upgraded to HTTPS, defaulting to https:// would silently skip
        past a domain that never upgrades at all."""
        mock_get.return_value = _resp(200)
        result = trace_redirects("example.com")
        self.assertEqual(result["original_url"], "http://example.com")

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_scheme_already_present_is_preserved(self, mock_get):
        mock_get.return_value = _resp(200)
        result = trace_redirects("https://example.com")
        self.assertEqual(result["original_url"], "https://example.com")

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_url_with_path_is_preserved(self, mock_get):
        mock_get.return_value = _resp(200)
        result = trace_redirects("http://example.com/some/path?x=1")
        self.assertEqual(result["original_url"], "http://example.com/some/path?x=1")

    # ------------------------------------------------------------------
    # Basic chain structure
    # ------------------------------------------------------------------

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_no_redirect_single_hop(self, mock_get):
        mock_get.return_value = _resp(200)
        result = trace_redirects("http://example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["total_hops"], 1)
        self.assertEqual(result["final_url"], "http://example.com")
        self.assertIsNone(result["chain"][0]["redirect_to"])
        self.assertIsNone(result["chain"][0]["issue"])

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_relative_location_header_resolved(self, mock_get):
        """requests does NOT auto-resolve a relative Location header
        when allow_redirects=False, confirmed via direct socket-level
        testing. Must be resolved manually against the current URL."""
        mock_get.side_effect = [
            _resp(301, {"Location": "/new-path"}),
            _resp(200),
        ]
        result = trace_redirects("http://example.com/old-path")
        self.assertEqual(result["chain"][0]["redirect_to"], "http://example.com/new-path")
        self.assertEqual(result["final_url"], "http://example.com/new-path")

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_absolute_location_header_used_as_is(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "https://other.com/page"}),
            _resp(200),
        ]
        result = trace_redirects("http://example.com")
        self.assertEqual(result["chain"][0]["redirect_to"], "https://other.com/page")

    # ------------------------------------------------------------------
    # TLS upgrade / downgrade detection
    # ------------------------------------------------------------------

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_http_to_https_upgrade_flagged_positively(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "https://example.com/"}),
            _resp(200),
        ]
        result = trace_redirects("http://example.com")
        self.assertFalse(any(i["type"] in ("tls_downgrade", "no_tls_upgrade") for i in result["issues_found"]))
        self.assertIn("HTTP to HTTPS upgrade present — good", result["security_notes"])

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_http_to_http_no_upgrade_flagged_high(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "http://example.com/page2"}),
            _resp(200),
        ]
        result = trace_redirects("http://example.com")
        no_upgrade = [i for i in result["issues_found"] if i["type"] == "no_tls_upgrade"]
        self.assertEqual(len(no_upgrade), 1)
        self.assertEqual(no_upgrade[0]["severity"], "high")

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_https_to_http_downgrade_flagged_critical(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "http://example.com/insecure"}),
            _resp(200),
        ]
        result = trace_redirects("https://example.com")
        downgrade = [i for i in result["issues_found"] if i["type"] == "tls_downgrade"]
        self.assertEqual(len(downgrade), 1)
        self.assertEqual(downgrade[0]["severity"], "critical")

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_https_stays_https_no_downgrade_note(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "https://example.com/page2"}),
            _resp(200),
        ]
        result = trace_redirects("https://example.com")
        self.assertFalse(any(i["type"] in ("tls_downgrade", "no_tls_upgrade") for i in result["issues_found"]))
        self.assertIn("Chain stayed on HTTPS throughout — good", result["security_notes"])

    # ------------------------------------------------------------------
    # Private IP detection
    # ------------------------------------------------------------------

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_private_ip_redirect_target_flagged(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "http://10.0.5.23/internal"}),
            _resp(200),
        ]
        result = trace_redirects("http://example.com")
        priv = [i for i in result["issues_found"] if i["type"] == "private_ip_leak"]
        self.assertEqual(len(priv), 1)
        self.assertEqual(priv[0]["severity"], "high")
        self.assertNotIn("No internal hostnames leaked in chain", result["security_notes"])

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_public_ip_redirect_target_not_flagged(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "http://8.8.8.8/page"}),
            _resp(200),
        ]
        result = trace_redirects("http://example.com")
        priv = [i for i in result["issues_found"] if i["type"] == "private_ip_leak"]
        self.assertEqual(len(priv), 0)

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_normal_hostname_not_flagged_as_private_ip(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "http://internal-sounding-name.com/"}),
            _resp(200),
        ]
        result = trace_redirects("http://example.com")
        priv = [i for i in result["issues_found"] if i["type"] == "private_ip_leak"]
        self.assertEqual(len(priv), 0)

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_loopback_address_flagged(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "http://127.0.0.1/admin"}),
            _resp(200),
        ]
        result = trace_redirects("http://example.com")
        priv = [i for i in result["issues_found"] if i["type"] == "private_ip_leak"]
        self.assertEqual(len(priv), 1)

    def test_hostname_is_private_ip_handles_none(self):
        """A malformed redirect target with no parseable
        host must not raise, just report not-private."""
        from tools.redirect_tracer import _hostname_is_private_ip
        self.assertFalse(_hostname_is_private_ip(None))
        self.assertFalse(_hostname_is_private_ip(""))

    # ------------------------------------------------------------------
    # Cross-domain detection (including the www-normalization fix)
    # ------------------------------------------------------------------

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_bare_to_www_not_flagged_cross_domain(self, mock_get):
        """example.com -> www.example.com is the single most common
        redirect pattern on the internet and must not be treated as
        a cross-domain finding."""
        mock_get.side_effect = [
            _resp(301, {"Location": "https://www.example.com/"}),
            _resp(200),
        ]
        result = trace_redirects("http://example.com")
        cross = [i for i in result["issues_found"] if i["type"] == "cross_domain_redirect"]
        self.assertEqual(len(cross), 0)

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_www_to_bare_not_flagged_cross_domain(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "https://example.com/"}),
            _resp(200),
        ]
        result = trace_redirects("http://www.example.com")
        cross = [i for i in result["issues_found"] if i["type"] == "cross_domain_redirect"]
        self.assertEqual(len(cross), 0)

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_genuinely_different_domain_flagged(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "https://totally-different-brand.net/"}),
            _resp(200),
        ]
        result = trace_redirects("https://example.com")
        cross = [i for i in result["issues_found"] if i["type"] == "cross_domain_redirect"]
        self.assertEqual(len(cross), 1)
        self.assertEqual(cross[0]["severity"], "high")

    # ------------------------------------------------------------------
    # Redirect loops
    # ------------------------------------------------------------------

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_redirect_loop_detected_and_stops(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "http://example.com/b"}),
            _resp(301, {"Location": "http://example.com"}),
        ]
        result = trace_redirects("http://example.com")
        self.assertTrue(result["success"])
        loop = [i for i in result["issues_found"] if i["type"] == "redirect_loop"]
        self.assertEqual(len(loop), 1)
        self.assertEqual(loop[0]["severity"], "medium")

    def test_redirect_loop_hop_number_references_a_real_chain_entry(self):
        """The loop issue's "hop" field was set to the hypothetical NEXT
        iteration number (the one that would have re-fetched the repeated
        URL), which never gets a chain entry recorded for it, break happens
        before any fetch or append. A consumer looking up chain[hop-1] to see
        which entry the loop issue refers to would get an IndexError or
        the wrong entry. The hop must reference the last entry that was
        actually recorded (len(chain)), which is the hop whose
        redirect_to points at the now-repeated URL."""
        with patch("tools.redirect_tracer.requests.Session.get") as mock_get:
            mock_get.side_effect = [
                _resp(301, {"Location": "http://example.com/b"}),
                _resp(301, {"Location": "http://example.com"}),
            ]
            result = trace_redirects("http://example.com")

        loop_issue = [i for i in result["issues_found"] if i["type"] == "redirect_loop"][0]
        chain_hop_numbers = [h["hop"] for h in result["chain"]]
        self.assertIn(loop_issue["hop"], chain_hop_numbers)
        self.assertEqual(loop_issue["hop"], len(result["chain"]))

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_self_redirecting_url_detected_as_loop(self, mock_get):
        mock_get.return_value = _resp(301, {"Location": "http://example.com"})
        result = trace_redirects("http://example.com")
        self.assertTrue(result["success"])
        loop = [i for i in result["issues_found"] if i["type"] == "redirect_loop"]
        self.assertEqual(len(loop), 1)

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_whitespace_only_location_resolves_to_self_and_is_flagged_as_loop(self, mock_get):
        """A Location header that is present but only whitespace is, per
        RFC 3986 reference resolution (as implemented by urljoin), an
        empty relative reference, it resolves back to the current URL,
        not to a distinct destination. This is correctly caught by the
        existing loop detection (current_url gets re-visited on the next
        iteration) rather than needing special-case handling. This test
        documents that behavior explicitly rather than leaving it as an
        implicit side effect of urljoin."""
        mock_get.side_effect = [
            _resp(301, {"Location": "   "}),
            _resp(200),
        ]
        result = trace_redirects("http://example.com")
        self.assertTrue(result["success"])
        loop = [i for i in result["issues_found"] if i["type"] == "redirect_loop"]
        self.assertEqual(len(loop), 1)
        self.assertEqual(result["chain"][0]["redirect_to"], "http://example.com")

    # ------------------------------------------------------------------
    # Chain length
    # ------------------------------------------------------------------

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_long_chain_flagged_low_severity(self, mock_get):
        hops = [_resp(301, {"Location": f"http://example.com/{i}"}) for i in range(6)]
        hops.append(_resp(200))
        mock_get.side_effect = hops
        result = trace_redirects("http://example.com")
        self.assertEqual(result["total_hops"], 7)
        long_chain = [i for i in result["issues_found"] if i["type"] == "long_chain"]
        self.assertEqual(len(long_chain), 1)
        self.assertEqual(long_chain[0]["severity"], "low")

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_short_chain_not_flagged_long(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "https://example.com/"}),
            _resp(200),
        ]
        result = trace_redirects("http://example.com")
        long_chain = [i for i in result["issues_found"] if i["type"] == "long_chain"]
        self.assertEqual(len(long_chain), 0)

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_max_hops_cap_enforced(self, mock_get):
        """A chain of unique, never-repeating, never-resolving redirects
        must stop at the hop cap rather than making unbounded requests."""
        hops = [_resp(301, {"Location": f"http://example.com/page{i}"}) for i in range(30)]
        mock_get.side_effect = hops
        result = trace_redirects("http://example.com")
        self.assertTrue(result["success"])
        self.assertLessEqual(mock_get.call_count, 15)
        max_hops = [i for i in result["issues_found"] if i["type"] == "max_hops_exceeded"]
        self.assertEqual(len(max_hops), 1)

    def test_max_hops_exceeded_hop_number_matches_chain_length(self):
        """The hop reference on this issue must equal len(chain), not a
        module constant that happens to equal it today by coincidence."""
        with patch("tools.redirect_tracer.requests.Session.get") as mock_get:
            hops = [_resp(301, {"Location": f"http://example.com/page{i}"}) for i in range(30)]
            mock_get.side_effect = hops
            result = trace_redirects("http://example.com")

        max_hops_issue = [i for i in result["issues_found"] if i["type"] == "max_hops_exceeded"][0]
        self.assertEqual(max_hops_issue["hop"], len(result["chain"]))

    # ------------------------------------------------------------------
    # Malformed responses
    # ------------------------------------------------------------------

    @patch("tools.redirect_tracer.requests.Session.get")
    def test_redirect_status_with_no_location_header(self, mock_get):
        mock_get.return_value = _resp(301, {})
        result = trace_redirects("http://example.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["total_hops"], 1)
        malformed = [i for i in result["issues_found"] if i["type"] == "malformed_redirect"]
        self.assertEqual(len(malformed), 1)

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    @patch("tools.redirect_tracer.requests.Session.get",
           side_effect=requests.exceptions.ConnectionError("refused"))
    def test_connection_error_returns_failure(self, _):
        result = trace_redirects("http://example.com")
        self.assertFalse(result["success"])
        self.assertIn("Connection failed", result["error"])

    @patch("tools.redirect_tracer.requests.Session.get",
           side_effect=requests.exceptions.Timeout("timed out"))
    def test_timeout_returns_failure(self, _):
        result = trace_redirects("http://example.com")
        self.assertFalse(result["success"])
        self.assertIn("Connection failed", result["error"])

    @patch("tools.redirect_tracer.requests.Session.get",
           side_effect=Exception("Unexpected error"))
    def test_unexpected_exception_returns_failure(self, _):
        result = trace_redirects("http://example.com")
        self.assertFalse(result["success"])
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)