import nmap

def port_scan(target: str, scan_type: str = "basic") -> dict:
    """
    Perform Nmap port scan on a target IP or domain.

    scan_type options:
    - "basic"   : Top 100 ports, fast (-F)
    - "service" : Service & version detection (-sV -F)
    - "os"      : OS detection, needs admin (-O -F)
    - "full"    : All 65535 ports, slow (-p-)
    - "vuln"    : Basic vulnerability scripts (--script vuln -F)
    """
    scan_args = {
        "basic":   "-F",
        "service": "-sV -F",
        "os":      "-O -F",
        "full":    "-p-",
        "vuln":    "--script vuln -F"
    }

    if scan_type not in scan_args:
        return {
            "success": False,
            "error": (
                f"Invalid scan_type '{scan_type}'. Valid options are: "
                f"{', '.join(scan_args.keys())}"
            ),
            "valid_scan_types": list(scan_args.keys()),
        }

    try:
        scanner = nmap.PortScanner()

        args = scan_args[scan_type]
        scanner.scan(hosts=target, arguments=args)

        results = []
        for host in scanner.all_hosts():
            host_data = {
                "host": host,
                "hostname": scanner[host].hostname(),
                "state": scanner[host].state(),
                "protocols": {}
            }

            for proto in scanner[host].all_protocols():
                ports = []
                for port, data in scanner[host][proto].items():
                    port_info = {
                        "port": port,
                        "state": data["state"],
                        "service": data["name"],
                    }
                    if data.get("product"):
                        port_info["product"] = data["product"]
                    if data.get("version"):
                        port_info["version"] = data["version"]
                    if data.get("script"):
                        port_info["scripts"] = data["script"]
                    ports.append(port_info)

                host_data["protocols"][proto] = ports

            results.append(host_data)

        return {
            "success": True,
            "target": target,
            "scan_type": scan_type,
            "hosts_found": len(results),
            "results": results
        }

    except nmap.PortScannerError as e:
        return {"success": False, "error": f"Nmap not found or not installed: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
