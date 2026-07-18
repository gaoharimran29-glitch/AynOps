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
