import dns.resolver
from utils.helpers import is_valid_domain, normalize_domain

PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"]


def _clean_name(value) -> str:
    return str(value).rstrip(".")


def _format_txt_record(record) -> str:
    chunks = getattr(record, "strings", None)
    if chunks:
        return "".join(
            chunk.decode("utf-8") if isinstance(chunk, bytes) else str(chunk)
            for chunk in chunks
        )
    return str(record)


def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_RESOLVERS
    return resolver


def dns_enumeration(domain: str) -> dict:
    """
    Enumerate DNS records for a domain.
    Returns A, AAAA, MX, NS, TXT, CNAME, SOA records.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    records = {}
    resolver = _make_resolver()

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=5, tcp=True)
            if rtype == "MX":
                records[rtype] = [
                    {"preference": r.preference, "exchange": _clean_name(r.exchange)}
                    for r in answers
                ]
            elif rtype == "SOA":
                r = answers[0]
                records[rtype] = {
                    "mname": _clean_name(r.mname),
                    "rname": _clean_name(r.rname),
                    "serial": r.serial,
                    "refresh": r.refresh,
                    "retry": r.retry,
                    "expire": r.expire,
                    "minimum": r.minimum
                }
            elif rtype == "TXT":
                records[rtype] = [_format_txt_record(r) for r in answers]
            elif rtype in {"NS", "CNAME"}:
                records[rtype] = [_clean_name(r) for r in answers]
            else:
                records[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            return {"success": False, "error": f"Domain {domain} does not exist"}
        except Exception:
            records[rtype] = []

    # Subdomain brute-force (common subdomains)
    common_subdomains = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn", "remote", "portal"]
    found_subdomains = []

    for sub in common_subdomains:
        try:
            full = f"{sub}.{domain}"
            resolver.resolve(full, "A", lifetime=3, tcp=True)
            found_subdomains.append(full)
        except Exception:
            pass

    return {
        "success": True,
        "domain": domain,
        "records": records,
        "subdomains_found": found_subdomains
    }
