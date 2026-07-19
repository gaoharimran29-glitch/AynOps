from utils.helpers import is_valid_domain, normalize_domain
import tldextract
import requests
import re
from concurrent.futures import ThreadPoolExecutor , as_completed

COMMON_SUFFIXES = [
    "",
    "assets",
    "backup",
    "backups",
    "dev",
    "prod",
    "production",
    "staging",
    "stage",
    "test",
    "media",
    "static",
    "files",
    "uploads",
    "images",
    "cdn",
    "storage",
    "data",
]

SUBDOMAIN_PREFIXES = [
    "assets",
    "backup",
    "media",
    "static",
    "cdn",
    "files",
]

def _sanitize_for_azure(name: str) -> str:
    """Azure storage account names allow only lowercase letters and
    digits; no hyphens, dots, or any other punctuation. A company
    name that itself contains a hyphen (e.g. "coca-cola") must be
    stripped here too, not just the suffix separator, or every
    generated candidate is still an invalid account name."""
    return re.sub(r"[^a-z0-9]", "", name.lower())

def generate_bucket_names(company_name: str , provider: str) -> list:
    """Generate bucket names for the given company names and return list"""
    if provider in ("AWS S3", "GCP"):
        bucket_names = []

        for i in COMMON_SUFFIXES:
            if i == "":
                bucket_names.append(company_name)
            else:
                x = company_name + "-" + i
                bucket_names.append(x)

        for i in SUBDOMAIN_PREFIXES:
            bucket_names.append(i + "." + company_name + ".com")
    else:
        bucket_names = []
        azure_company_name = _sanitize_for_azure(company_name)

        for i in COMMON_SUFFIXES:
            if i == "":
                bucket_names.append(azure_company_name)
            else:
                x = azure_company_name + i
                bucket_names.append(x)

        for i in SUBDOMAIN_PREFIXES:
            bucket_names.append(i + azure_company_name)

    bucket_names = list(dict.fromkeys(bucket_names))
    return bucket_names

def url_response(url: str) -> dict:
    """Check bucket urls and return the response results"""
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "AynOps Recon"})
    except Exception as e:
        return {
            "url": url,
            "status": "ERROR",
            "severity": "INFO",
            "note": str(e)
        }

    if response.status_code == 200:
        return {
                "url": url ,
                "status":"PUBLIC" , 
                "severity":"CRITICAL" , 
                "note": "Bucket is publicly listable — files are exposed"
            }
    elif response.status_code == 403:
        return {
                "url": url ,
                "status": "EXISTS_PRIVATE" , 
                "severity":"INFO" ,
                "note": "Bucket exists but is not publicly accessible"
            }
    
    elif response.status_code == 404:
        return {
            "url": url,
            "status": "NOT_FOUND" ,
            "severity": "INFO" ,
            "note":"Bucket does not exist"
        }
    
    else:
        return {
            "url":url,
            "status":"NOT_FOUND",
            "severity":"INFO",
            "note": f"URL Respond with status code {response.status_code}"
        }
    
def check_provider(bucket, provider):
    """Build url with bucket names and cloud provider , then send url for checking to url_response"""
    if provider == "AWS S3":
        if "." in bucket:
            url = f"https://s3.amazonaws.com/{bucket}/"
        else:
            url = f"https://{bucket}.s3.amazonaws.com/"
    elif provider == "GCP":
        url = f"https://storage.googleapis.com/{bucket}/"
    elif provider == "AZURE":
        url =f"https://{bucket}.blob.core.windows.net/{bucket}?restype=container&comp=list"  
    else:
        raise ValueError(f"Unknown provider: {provider}")

    result = url_response(url)
    return {
        "bucket_name": bucket ,
        "provider":provider,
        **result
    }

def cloud_exposure_check(domain: str) -> dict:
    """Takes domain as input and return complete metrics and results for cloud urls exposed or not for a company"""
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}
    
    company_name = tldextract.extract(domain).domain
    default_buckets = generate_bucket_names(company_name, "AWS S3")
    azure_buckets = generate_bucket_names(company_name, "AZURE")

    findings = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for bucket in default_buckets:
            futures.append(executor.submit(check_provider , bucket , "AWS S3"))
            futures.append(executor.submit(check_provider , bucket , "GCP"))

        for bucket in azure_buckets:
            futures.append(executor.submit(check_provider , bucket , "AZURE"))

        for future in as_completed(futures):
            try:
                findings.append(future.result())
            except Exception as e:
                findings.append({
                    "status": "ERROR",
                    "note": str(e)
                })
        
    total_exposed = len([item for item in findings if item.get("status") == "PUBLIC"])
    total_private = len([item for item in findings if item.get("status") == "EXISTS_PRIVATE"])
    total_not_found = len([item for item in findings if item.get("status") == "NOT_FOUND"])

    return {
        "success": True,
        "domain": domain ,
        "buckets_checked": len(default_buckets) * 2 + len(azure_buckets) ,
        "findings": findings ,
        "total_exposed": total_exposed,
        "total_private": total_private,
        "total_not_found": total_not_found
    }