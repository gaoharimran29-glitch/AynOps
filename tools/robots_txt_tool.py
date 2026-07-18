import requests
from urllib.parse import urlparse
from utils.helpers import is_valid_domain

def robots_txt_inspect(domain: str) -> dict:
    """
    Fetch and parse the robots.txt file for a given domain to reveal hidden directories and sitemaps.
    """
    try:
        if not is_valid_domain(domain):
            return {"success": False, "error": "Invalid domain format"}

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        url_https = f"https://{domain}/robots.txt"
        url_http = f"http://{domain}/robots.txt"
        
        response = None
        try:
            response = requests.get(url_https, timeout=10.0, headers=headers)
            response.raise_for_status()
        except requests.RequestException:
            # Fallback to HTTP
            response = requests.get(url_http, timeout=10.0, headers=headers)
            response.raise_for_status()
            
        content = response.text
        robots_url = response.url
        
        # We will parse robots.txt into rules by User-agent
        rules = []
        current_agent = "*"
        current_allow = []
        current_disallow = []
        
        sitemaps = []
        crawl_delay = None
        host = None

        for line in content.splitlines():
            # Strip inline comments first
            if "#" in line:
                line = line.split("#", 1)[0]
            line = line.strip()
            
            if not line:
                continue
                
            line_lower = line.lower()
            
            if line_lower.startswith("user-agent:"):
                # If we were tracking a previous agent that had rules, save it
                if current_allow or current_disallow:
                    rules.append({
                        "user_agent": current_agent,
                        "allow": list(dict.fromkeys(current_allow)),
                        "disallow": list(dict.fromkeys(current_disallow))
                    })
                    current_allow = []
                    current_disallow = []
                
                current_agent = line.split(":", 1)[1].strip()
                
            elif line_lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    current_disallow.append(path)
                    
            elif line_lower.startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    current_allow.append(path)
                    
            elif line_lower.startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                if sitemap:
                    sitemaps.append(sitemap)

            elif line_lower.startswith("crawl-delay:"):
                # Per RFC 9309, Crawl-delay is a per-User-agent directive.
                # The top-level return shape exposes the last-seen value.
                value = line.split(":", 1)[1].strip()
                if value:
                    crawl_delay = value

            elif line_lower.startswith("host:"):
                # `Host:` is a non-standard but widely-recognized directive
                # (originally from Yandex) used to specify the primary mirror.
                value = line.split(":", 1)[1].strip()
                if value:
                    host = value

        # Add the last rule block if it has anything
        if current_allow or current_disallow or current_agent == "*":
            # Avoid adding empty duplicate '*' rules if we haven't seen anything
            if current_allow or current_disallow or not any(r["user_agent"] == "*" for r in rules):
                rules.append({
                    "user_agent": current_agent,
                    "allow": list(dict.fromkeys(current_allow)),
                    "disallow": list(dict.fromkeys(current_disallow))
                })

        # For backward compatibility and top-level summary, aggregate all unique paths
        all_allowed = []
        all_disallowed = []
        for r in rules:
            all_allowed.extend(r["allow"])
            all_disallowed.extend(r["disallow"])
            
        return {
            "success": True,
            "domain": domain,
            "robots_url": robots_url,
            "allowed_paths": list(dict.fromkeys(all_allowed)),
            "disallowed_paths": list(dict.fromkeys(all_disallowed)),
            "sitemaps": list(dict.fromkeys(sitemaps)),
            "crawl_delay": crawl_delay,
            "host": host,
            "rules": rules
        }

    except requests.RequestException as e:
        return {"success": False, "error": f"Failed to fetch robots.txt: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
