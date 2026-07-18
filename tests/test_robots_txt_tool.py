import pytest
from unittest.mock import patch, MagicMock
from tools.robots_txt_tool import robots_txt_inspect
import requests

def test_robots_txt_inspect_invalid_domain():
    result = robots_txt_inspect("invalid domain")
    assert result["success"] is False
    assert "Invalid domain format" in result["error"]

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_happy_path_https(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "https://example.com/robots.txt"
    mock_response.text = """
User-agent: *
Disallow: /admin # No admins allowed
Allow: /admin/public
Disallow: /backup/

User-agent: Googlebot
Disallow: /secret/
Sitemap: https://example.com/sitemap.xml
"""
    mock_get.return_value = mock_response
    
    result = robots_txt_inspect("example.com")
    
    assert result["success"] is True
    assert result["domain"] == "example.com"
    assert result["robots_url"] == "https://example.com/robots.txt"
    
    # Check top level aggregations
    assert "/admin" in result["disallowed_paths"]
    assert "/backup/" in result["disallowed_paths"]
    assert "/secret/" in result["disallowed_paths"]
    assert result["allowed_paths"] == ["/admin/public"]
    assert result["sitemaps"] == ["https://example.com/sitemap.xml"]
    
    # Check rule sets
    assert len(result["rules"]) == 2
    assert result["rules"][0]["user_agent"] == "*"
    assert result["rules"][0]["disallow"] == ["/admin", "/backup/"]
    assert result["rules"][0]["allow"] == ["/admin/public"]
    
    assert result["rules"][1]["user_agent"] == "Googlebot"
    assert result["rules"][1]["disallow"] == ["/secret/"]
    assert result["rules"][1]["allow"] == []

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_fallback_to_http(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "http://example.com/robots.txt"
    mock_response.text = "User-agent: *\nDisallow: /private"
    
    mock_get.side_effect = [requests.RequestException("Connection error"), mock_response]
    
    result = robots_txt_inspect("example.com")
    
    assert result["success"] is True
    assert result["domain"] == "example.com"
    assert result["robots_url"] == "http://example.com/robots.txt"
    assert result["disallowed_paths"] == ["/private"]
    assert mock_get.call_count == 2

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_failure(mock_get):
    mock_get.side_effect = requests.RequestException("Timeout")

    result = robots_txt_inspect("example.com")

    assert result["success"] is False
    assert "Failed to fetch robots.txt" in result["error"]

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_parses_crawl_delay_and_host(mock_get):
    """Crawl-delay and Host directives should be parsed, not always None.

    Regression test for the bug introduced in PR #98 where the return shape
    advertised crawl_delay/host fields but the parser never populated them.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "https://example.com/robots.txt"
    mock_response.text = (
        "User-agent: *\n"
        "Crawl-delay: 10\n"
        "Host: example.com\n"
        "Disallow: /private\n"
    )
    mock_get.return_value = mock_response

    result = robots_txt_inspect("example.com")

    assert result["success"] is True
    assert result["crawl_delay"] == "10"
    assert result["host"] == "example.com"
    assert result["disallowed_paths"] == ["/private"]

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_crawl_delay_and_host_absent_when_not_present(mock_get):
    """crawl_delay and host remain None when the directives are absent.

    Locks in the backward-compatible default for robots.txt files that do
    not include Crawl-delay or Host directives.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "https://example.com/robots.txt"
    mock_response.text = "User-agent: *\nDisallow: /private\n"
    mock_get.return_value = mock_response

    result = robots_txt_inspect("example.com")

    assert result["success"] is True
    assert result["crawl_delay"] is None
    assert result["host"] is None

@patch("tools.robots_txt_tool.requests.get")
def test_robots_txt_inspect_crawl_delay_uses_last_seen_value(mock_get):
    """When multiple Crawl-delay directives appear, the last one wins.

    The top-level return shape exposes a single crawl_delay value (it is
    semantically per-User-agent per RFC 9309). The parser uses last-seen
    as the pragmatic top-level summary.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "https://example.com/robots.txt"
    mock_response.text = (
        "User-agent: *\n"
        "Crawl-delay: 5\n"
        "User-agent: Googlebot\n"
        "Crawl-delay: 30\n"
    )
    mock_get.return_value = mock_response

    result = robots_txt_inspect("example.com")

    assert result["success"] is True
    assert result["crawl_delay"] == "30"
