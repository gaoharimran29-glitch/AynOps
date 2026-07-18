from urllib.parse import urlparse
import ipaddress
import socket

def asn_lookup(target: str) -> dict:
    """
    Find the Autonomous System Number (ASN) and network ownership
    for a domain or IP using Team Cymru WHOIS. Useful for identifying
    hosting provider and network ownership. No API key required.

    Args:
        target (str): Domain or IP address

    Returns:
        dict: ASN and network ownership details
    """
    try:
        target = target.strip()

        if "://" in target:
            parsed = urlparse(target)
            target = parsed.netloc if parsed.netloc else parsed.path

        if target.count(":") == 1 and not target.startswith("["):
            host, possible_port = target.rsplit(":", 1)
            if possible_port.isdigit():
                target = host

        try:
            ipaddress.ip_address(target)
            ip = target
        except ValueError:
            ip = socket.getaddrinfo(target, None)[0][4][0]

        # Team Cymru bulk WHOIS query (port 43 is the standard WHOIS port).
        # Format documented at https://team-cymru.com/community-services/ip-to-asn-mapping/
        query = f"begin\nverbose\n{ip}\nend\n"
        with socket.create_connection(("whois.cymru.com", 43), timeout=15) as sock:
            sock.sendall(query.encode())
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            # AS names occasionally contain non-ASCII; replace avoids decode crashes.
            response = b"".join(chunks).decode("utf-8", errors="replace")

        # Team Cymru verbose response is pipe-delimited. First line is a header
        # (e.g. "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name"),
        # followed by one data line per queried IP. We accept the first line
        # whose first field is numeric (this skips the header and any blank lines).
        # Field indices: 0=AS, 1=IP, 2=BGP Prefix, 3=CC, 4=Registry,
        #                5=Allocated, 6=AS Name
        lines = [line for line in response.strip().splitlines() if line.strip()]
        if not lines:
            return {
                "success": False,
                "error": "Unexpected or malformed response from Team Cymru WHOIS",
            }

        data_line = None
        for line in lines:
            fields = [f.strip() for f in line.split("|")]
            if len(fields) >= 7 and fields[0].isdigit():
                data_line = fields
                break

        if not data_line:
            return {
                "success": False,
                "error": "Unexpected or malformed response from Team Cymru WHOIS",
            }

        # Normalize AS number to the "AS<number>" convention (Team Cymru returns
        # the bare number; the prefix keeps downstream consumers consistent).
        asn_val = data_line[0]
        asn_string = f"AS{asn_val}" if not asn_val.startswith("AS") else asn_val

        return {
            "success": True,
            "ip": ip,
            "asn": asn_string,
            "bgp_prefix": data_line[2],
            "country": data_line[3],
            "registry": data_line[4],
            "allocated": data_line[5],
            "organization": data_line[6],
        }

    except socket.gaierror:
        return {"success": False, "error": "Failed to resolve domain"}
    except socket.timeout:
        return {"success": False, "error": "Team Cymru WHOIS request timed out"}
    except (ConnectionError, OSError) as e:
        return {
            "success": False,
            "error": f"Could not connect to Team Cymru WHOIS service: {e}",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
