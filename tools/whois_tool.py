import socket
import whois
from utils.helpers import is_valid_domain, normalize_domain

WHOIS_TIMEOUT_SECONDS = 10

def whois_lookup(domain: str) -> dict:
    """Perform WHOIS lookup for a domain."""
    try:
        domain = normalize_domain(domain)
        if not is_valid_domain(domain):
            return {"success": False, "error": "Invalid domain format"}

        result = whois.whois(domain, timeout=WHOIS_TIMEOUT_SECONDS)

        def safe_date(d):
            """Convert datetime objects or lists of datetimes to strings."""
            if d is None:
                return None
            
            if isinstance(d , list):
                return [str(item) for item in d]

            return str(d)
        
        return {
            "success": True,
            "domain": result.domain_name,
            "registrar": result.registrar,
            "registrar_url": result.registrar_url ,
            "whois_server": result.whois_server,
            "creation_date": safe_date(result.creation_date),
            "expiration_date": safe_date(result.expiration_date),
            "updated_date": safe_date(result.updated_date),
            "name_servers": result.name_servers,
            "status": result.status,
            "emails": result.emails,
            "dnssec": result.dnssec,
            "country": result.country,
            "org": result.org
        }
    except (socket.timeout, TimeoutError) as e:
        return {"success": False, "error": f"WHOIS lookup timed out after {WHOIS_TIMEOUT_SECONDS} seconds"}
    except Exception as e:
        return {"success": False, "error": str(e)}