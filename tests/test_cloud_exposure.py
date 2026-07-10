import pytest
from unittest.mock import patch, MagicMock
import requests

from tools.cloud_exposure_tool import (
    generate_bucket_names,
    url_response,
    check_provider,
    cloud_exposure_check,
    COMMON_SUFFIXES,
    SUBDOMAIN_PREFIXES
)

def test_generate_bucket_names_basic():
    company = "google"
    names = generate_bucket_names(company)
    
    assert company in names
    assert f"{company}-backup" in names
    assert f"backup.{company}.com" in names
    expected_count = len(COMMON_SUFFIXES) + len(SUBDOMAIN_PREFIXES)
    assert len(names) == expected_count

def test_generate_bucket_names_uniqueness():
    # Duplicates should be filtered out by dict.fromkeys()
    names = generate_bucket_names("test")
    assert len(names) == len(set(names))

@patch("tools.cloud_exposure_tool.requests.get")
def test_url_response_public(mock_get):
    # Simulate a 200 OK Response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_get.return_value = mock_response
    
    result = url_response("https://example.s3.amazonaws.com/")
    assert result["status"] == "PUBLIC"
    assert result["severity"] == "CRITICAL"

@patch("tools.cloud_exposure_tool.requests.get")
def test_url_response_private(mock_get):
    # Simulate a 403 Forbidden Response
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_get.return_value = mock_response
    
    result = url_response("https://example.s3.amazonaws.com/")
    assert result["status"] == "EXISTS_PRIVATE"
    assert result["severity"] == "INFO"

@patch("tools.cloud_exposure_tool.requests.get")
def test_url_response_not_found(mock_get):
    # Simulate a 404 Not Found Response
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response
    
    result = url_response("https://example.s3.amazonaws.com/")
    assert result["status"] == "NOT_FOUND"

@patch("tools.cloud_exposure_tool.requests.get")
def test_url_response_exception(mock_get):
    # Simulate a network timeout or connection failure
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")
    
    result = url_response("https://example.s3.amazonaws.com/")
    assert result["status"] == "ERROR"
    assert "Connection timed out" in result["note"]

@patch("tools.cloud_exposure_tool.url_response")
def test_check_provider_aws(mock_url_response):
    mock_url_response.return_value = {"status": "NOT_FOUND", "severity": "INFO", "note": "Bucket does not exist"}
    
    result = check_provider("mybucket", "AWS S3")
    assert result["provider"] == "AWS S3"
    assert result["bucket_name"] == "mybucket"
    mock_url_response.assert_called_once_with("https://mybucket.s3.amazonaws.com/")

@patch("tools.cloud_exposure_tool.url_response")
def test_check_provider_gcp(mock_url_response):
    mock_url_response.return_value = {"status": "NOT_FOUND", "severity": "INFO", "note": "Bucket does not exist"}
    
    result = check_provider("mybucket", "GCP")
    mock_url_response.assert_called_once_with("https://storage.googleapis.com/mybucket/")

@patch("tools.cloud_exposure_tool.url_response")
def test_check_provider_azure(mock_url_response):
    mock_url_response.return_value = {"status": "NOT_FOUND", "severity": "INFO", "note": "Bucket does not exist"}
    
    result = check_provider("mybucket", "AZURE")
    expected_url = "https://mybucket.blob.core.windows.net/mybucket?restype=container&comp=list"
    mock_url_response.assert_called_once_with(expected_url)

def test_check_provider_invalid():
    with pytest.raises(ValueError, match="Unknown provider: UNKNOWN_CLOUD"):
        check_provider("mybucket", "UNKNOWN_CLOUD")

@patch("tools.cloud_exposure_tool.is_valid_domain")
def test_cloud_exposure_check_invalid_domain(mock_is_valid):
    mock_is_valid.return_value = False
    
    result = cloud_exposure_check("invalid_domain_here")
    assert result["success"] is False
    assert result["error"] == "Invalid domain format"

@patch("tools.cloud_exposure_tool.is_valid_domain")
@patch("tools.cloud_exposure_tool.check_provider")
def test_cloud_exposure_check_success_and_aggregates(mock_check_provider, mock_is_valid):
    mock_is_valid.return_value = True
    
    call_count = 0
    def side_effect_callback(bucket, provider):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {"status": "PUBLIC", "bucket_name": bucket, "provider": provider}
        elif call_count == 2:
            return {"status": "EXISTS_PRIVATE", "bucket_name": bucket, "provider": provider}
        else:
            return {"status": "NOT_FOUND", "bucket_name": bucket, "provider": provider}
            
    mock_check_provider.side_effect = side_effect_callback
    
    result = cloud_exposure_check("testcompany.com")
    
    assert result["success"] is True
    assert result["domain"] == "testcompany.com"
    assert result["total_exposed"] == 1
    assert result["total_private"] == 1
    expected_not_found = result["buckets_checked"] - 2
    assert result["total_not_found"] == expected_not_found