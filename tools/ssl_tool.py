import ssl
import socket
from datetime import datetime, timezone
from utils.helpers import is_valid_domain, normalize_domain

def ssl_inspect(domain: str, port: int = 443) -> dict:
    """
    Inspect SSL/TLS certificate details for a domain.
    Returns cert validity, issuer, SANs, expiry, and cipher info.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    try:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Create raw socket, wrap it, and manage the lifecycle of the wrapper
        raw_sock = socket.create_connection((domain, port), timeout=10)
        with context.wrap_socket(raw_sock, server_hostname=domain) as conn:
            cert = conn.getpeercert()
            cipher = conn.cipher()
            tls_version = conn.version()

        # Parse dates and make them timezone-aware (UTC)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days

        # Subject Alternative Names
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        def rdn(rdns):
            return {k: v for rdn in rdns for k, v in rdn}

        return {
            "success": True,
            "domain": domain,
            "port": port,
            "tls_version": tls_version,
            "cipher": {
                "name": cipher[0],
                "protocol": cipher[1],
                "bits": cipher[2]
            },
            "certificate": {
                "subject": rdn(cert.get("subject", [])),
                "issuer": rdn(cert.get("issuer", [])),
                "serial_number": cert.get("serialNumber"),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_until_expiry": days_left,
                "expired": days_left < 0,
                "expiring_soon": 0 <= days_left <= 30,
                "subject_alt_names": sans,
                "version": cert.get("version")
            }
        }

    except ssl.SSLCertVerificationError as e:
        return {"success": False, "error": f"SSL verification failed: {str(e)}"}
    except socket.timeout:
        return {"success": False, "error": "Connection timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}