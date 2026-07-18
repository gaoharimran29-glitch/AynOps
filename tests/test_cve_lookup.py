from unittest.mock import Mock, MagicMock, patch, call
import unittest
from tools.cve_tool import cve_lookup, _cve_affects_version


def _make_raw_cve(cve_id, cpe_matches, configurations=None):
    """Build a raw NVD vulnerability item with the given cpeMatch entries.

    If ``configurations`` is None (default), a single configuration/node is
    created wrapping ``cpe_matches``. Pass an explicit ``configurations`` value
    to override the structure entirely.
    """
    cve = {
        "id": cve_id,
        "published": "2021-01-01T00:00:00.000",
        "lastModified": "2021-01-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
        "metrics": {
            "cvssMetricV31": [
                {"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}
            ]
        },
    }
    if configurations is not None:
        cve["configurations"] = configurations
    else:
        cve["configurations"] = [{"nodes": [{"cpeMatch": cpe_matches}]}]
    return {"cve": cve}


class TestCveLookup(unittest.TestCase):

    @patch("tools.cve_tool.requests.get")
    def test_cve_lookup_returns_nvd_results(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-41773",
                        "published": "2021-10-05T12:15:07.000",
                        "lastModified": "2024-11-21T05:31:44.123",
                        "descriptions": [{"lang": "en", "value": "Path traversal vulnerability"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"baseSeverity": "CRITICAL", "cvssData": {"baseScore": 9.8}}
                            ]
                        },
                    }
                }
            ],
        }
        mock_get.return_value = response

        result = cve_lookup("apache", "2.4.49")

        self.assertTrue(result["success"])
        self.assertEqual(result["software"], "apache")
        self.assertEqual(result["version"], "2.4.49")
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-2021-41773")
        self.assertEqual(result["cves"][0]["severity"], "CRITICAL")
        self.assertEqual(result["cves"][0]["score"], 9.8)
        mock_get.assert_called_once()

    @patch("tools.cve_tool.requests.get")
    def test_cve_lookup_empty_results(self, mock_get):
        response = Mock()
        response.json.return_value = {"totalResults": 0, "vulnerabilities": []}
        mock_get.return_value = response

        result = cve_lookup("unknownsoftware", "9.9.9")
        self.assertTrue(result["success"])
        self.assertEqual(result["total_results"], 0)
        self.assertEqual(result["cves"], [])

    def test_cve_lookup_empty_software_rejected(self):
        result = cve_lookup("", "1.0")
        self.assertFalse(result["success"])
        self.assertIn("required", result["error"])

    def test_cve_lookup_empty_version_rejected(self):
        result = cve_lookup("apache", "")
        self.assertFalse(result["success"])

    def test_cve_lookup_whitespace_only_rejected(self):
        result = cve_lookup("   ", "   ")
        self.assertFalse(result["success"])

    @patch("tools.cve_tool.requests.get")
    def test_cve_lookup_multiple_cves(self, mock_get):
        def make_vuln(cve_id, score):
            return {
                "cve": {
                    "id": cve_id,
                    "published": "2021-01-01T00:00:00.000",
                    "lastModified": "2021-01-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"baseSeverity": "HIGH", "cvssData": {"baseScore": score}}
                        ]
                    },
                }
            }

        response = Mock()
        response.json.return_value = {
            "totalResults": 2,
            "vulnerabilities": [make_vuln("CVE-2021-00001", 8.0), make_vuln("CVE-2021-00002", 7.5)],
        }
        mock_get.return_value = response

        result = cve_lookup("nginx", "1.18")
        self.assertEqual(len(result["cves"]), 2)
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-2021-00001")

    @patch("tools.cve_tool.requests.get", side_effect=Exception("NVD unreachable"))
    def test_cve_lookup_exception_caught(self, _):
        result = cve_lookup("apache", "2.4")
        self.assertFalse(result["success"])
        self.assertIn("NVD unreachable", result["error"])

    # ------------------------------------------------------------------
    # Stage 1 / 2 / 3 multi-stage behavior
    # ------------------------------------------------------------------

    @patch("tools.cve_tool.requests.get")
    def test_stage1_returns_results_without_filtering(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-41773",
                        "published": "2021-10-05T12:15:07.000",
                        "lastModified": "2024-11-21T05:31:44.123",
                        "descriptions": [{"lang": "en", "value": "Path traversal"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"baseSeverity": "CRITICAL", "cvssData": {"baseScore": 9.8}}
                            ]
                        },
                    }
                }
            ],
        }
        mock_get.return_value = response

        result = cve_lookup("apache", "2.4.49")

        self.assertTrue(result["success"])
        self.assertEqual(result["version_filtering_applied"], False)
        self.assertEqual(mock_get.call_count, 1)
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-2021-41773")

    @patch("tools.cve_tool.requests.get")
    def test_stage2_stage3_falls_back_and_filters(self, mock_get):
        empty_response = Mock()
        empty_response.json.return_value = {"totalResults": 0, "vulnerabilities": []}

        cve_matching_1 = _make_raw_cve(
            "CVE-2020-0001",
            [{"vulnerable": True, "versionStartIncluding": "1.0.0", "versionEndIncluding": "2.0.0"}],
        )
        cve_matching_2 = _make_raw_cve(
            "CVE-2020-0002",
            [{"vulnerable": True, "versionStartIncluding": "1.5.0", "versionEndExcluding": "3.0.0"}],
        )
        cve_non_matching = _make_raw_cve(
            "CVE-2020-0003",
            [{"vulnerable": True, "versionStartIncluding": "5.0.0", "versionEndIncluding": "6.0.0"}],
        )
        data_response = Mock()
        data_response.json.return_value = {
            "totalResults": 3,
            "vulnerabilities": [cve_matching_1, cve_matching_2, cve_non_matching],
        }

        mock_get.side_effect = [empty_response, data_response]

        result = cve_lookup("someproduct", "1.5.0")

        self.assertTrue(result["success"])
        self.assertEqual(result["version_filtering_applied"], True)
        self.assertEqual(mock_get.call_count, 2)
        self.assertEqual(len(result["cves"]), 2)
        cve_ids = {c["cve_id"] for c in result["cves"]}
        self.assertEqual(cve_ids, {"CVE-2020-0001", "CVE-2020-0002"})

    @patch("tools.cve_tool.requests.get")
    def test_stage3_filters_out_non_matching_version(self, mock_get):
        empty_response = Mock()
        empty_response.json.return_value = {"totalResults": 0, "vulnerabilities": []}

        cve_1 = _make_raw_cve(
            "CVE-2020-0001",
            [{"vulnerable": True, "versionStartIncluding": "5.0.0", "versionEndIncluding": "6.0.0"}],
        )
        cve_2 = _make_raw_cve(
            "CVE-2020-0002",
            [{"vulnerable": True, "versionEndExcluding": "1.0.0"}],
        )
        data_response = Mock()
        data_response.json.return_value = {
            "totalResults": 2,
            "vulnerabilities": [cve_1, cve_2],
        }

        mock_get.side_effect = [empty_response, data_response]

        result = cve_lookup("someproduct", "2.5.0")

        self.assertTrue(result["success"])
        self.assertEqual(result["version_filtering_applied"], True)
        self.assertEqual(len(result["cves"]), 0)
        self.assertEqual(result["total_results"], 0)

    @patch("tools.cve_tool.requests.get")
    def test_cve_with_no_configurations_excluded_by_filter(self, mock_get):
        empty_response = Mock()
        empty_response.json.return_value = {"totalResults": 0, "vulnerabilities": []}

        cve_no_config = {
            "cve": {
                "id": "CVE-2020-0001",
                "published": "2021-01-01T00:00:00.000",
                "lastModified": "2021-01-01T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "metrics": {
                    "cvssMetricV31": [
                        {"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}
                    ]
                },
                # NOTE: no "configurations" key on purpose.
            }
        }
        data_response = Mock()
        data_response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [cve_no_config],
        }

        mock_get.side_effect = [empty_response, data_response]

        result = cve_lookup("someproduct", "1.0.0")

        self.assertTrue(result["success"])
        self.assertEqual(result["version_filtering_applied"], True)
        self.assertEqual(len(result["cves"]), 0)

    @patch("tools.cve_tool.requests.get")
    def test_invalid_target_version_skips_filter(self, mock_get):
        empty_response = Mock()
        empty_response.json.return_value = {"totalResults": 0, "vulnerabilities": []}

        cve_1 = _make_raw_cve(
            "CVE-2020-0001",
            [{"vulnerable": True, "versionStartIncluding": "5.0.0", "versionEndIncluding": "6.0.0"}],
        )
        cve_2 = _make_raw_cve(
            "CVE-2020-0002",
            [{"vulnerable": True, "versionEndExcluding": "1.0.0"}],
        )
        data_response = Mock()
        data_response.json.return_value = {
            "totalResults": 2,
            "vulnerabilities": [cve_1, cve_2],
        }

        mock_get.side_effect = [empty_response, data_response]

        result = cve_lookup("someproduct", "abc")

        self.assertTrue(result["success"])
        self.assertEqual(result["version_filtering_applied"], True)
        # Unparseable target version => filter is skipped, all CVEs included.
        self.assertEqual(len(result["cves"]), 2)

    # ------------------------------------------------------------------
    # Version-range filtering unit tests (target _cve_affects_version)
    # ------------------------------------------------------------------

    def test_version_start_including(self):
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "versionStartIncluding": "1.0.0"}
                            ]
                        }
                    ]
                }
            ]
        }
        self.assertTrue(_cve_affects_version(cve, "1.5.0"))
        self.assertTrue(_cve_affects_version(cve, "1.0.0"))  # boundary inclusive
        self.assertFalse(_cve_affects_version(cve, "0.9.9"))

    def test_version_end_excluding(self):
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "versionEndExcluding": "2.0.0"}
                            ]
                        }
                    ]
                }
            ]
        }
        self.assertTrue(_cve_affects_version(cve, "1.9.9"))
        self.assertFalse(_cve_affects_version(cve, "2.0.0"))  # excluded boundary

    def test_non_vulnerable_cpe_match_ignored(self):
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "versionStartIncluding": "1.0.0",
                                    "versionEndIncluding": "2.0.0",
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        # Non-vulnerable matches are ignored, so 1.5.0 is not affected.
        self.assertFalse(_cve_affects_version(cve, "1.5.0"))

if __name__ == "__main__":
    unittest.main(verbosity=2)