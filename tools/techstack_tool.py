import requests
from utils.helpers import is_valid_domain, normalize_domain

def tech_stack_detect(domain: str) -> dict:
    """
    Detect technology stack of a website.
    Identifies web server, frameworks, CMS, CDN, analytics, and security headers.
    """
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"success": False, "error": "Invalid domain format"}

    try:
        url = f"https://{domain}"
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"})

        headers = {k.lower(): v for k, v in resp.headers.items()}
        html    = resp.text.lower()
        tech    = {}

        # ── Web Server ──
        if "server" in headers:
            tech["web_server"] = headers["server"]

        # ── Powered By ──
        if "x-powered-by" in headers:
            tech["powered_by"] = headers["x-powered-by"]

        # ── CDN Detection ──
        cdn_signatures = {
            "Cloudflare":   ["cf-ray", "cf-cache-status"],
            "Fastly":       ["x-fastly-request-id"],
            "Akamai":       ["x-akamai-transformed"],
            "AWS CloudFront": ["x-amz-cf-id"],
            "Vercel":       ["x-vercel-id"],
            "Netlify":      ["x-nf-request-id"],
        }
        cdns = [name for name, hdrs in cdn_signatures.items() if any(h in headers for h in hdrs)]
        if cdns:
            tech["cdn"] = cdns

        # ── CMS Detection ──
        cms_signatures = {
            "WordPress":  ["wp-content", "wp-includes", "wordpress"],
            "Drupal":     ["drupal.js", "drupal.min.js", "/sites/default/files"],
            "Joomla":     ["/media/jui/", "joomla"],
            "Shopify":    ["cdn.shopify.com", "shopify.com/s/files"],
            "Wix":        ["wix.com", "wixstatic.com"],
            "Squarespace":["squarespace.com", "static.squarespace.com"],
            "Ghost":      ["ghost.io", "content/themes/ghost"],
        }
        cms_found = [name for name, sigs in cms_signatures.items() if any(s in html for s in sigs)]
        if cms_found:
            tech["cms"] = cms_found

        # ── JavaScript Frameworks ──
        js_signatures = {
            "React":      ["react.js", "react.min.js", "_react", "__react"],
            "Vue.js":     ["vue.js", "vue.min.js", "__vue__"],
            "Angular":    ["angular.js", "ng-version", "angular/core"],
            "Next.js":    ["_next/static", "__next"],
            "Nuxt.js":    ["_nuxt/", "__nuxt"],
            "jQuery":     ["jquery.js", "jquery.min.js"],
            "Bootstrap":  ["bootstrap.css", "bootstrap.min.css", "bootstrap.js"],
            "Tailwind":   ["tailwindcss", "tailwind.css"],
        }
        js_found = [name for name, sigs in js_signatures.items() if any(s in html for s in sigs)]
        if js_found:
            tech["javascript_frameworks"] = js_found

        # ── Analytics ──
        analytics_signatures = {
            "Google Analytics":   ["google-analytics.com", "gtag(", "ga("],
            "Google Tag Manager": ["googletagmanager.com"],
            "Hotjar":             ["hotjar.com"],
            "Mixpanel":           ["mixpanel.com"],
            "Segment":            ["segment.com", "analytics.js"],
            "Facebook Pixel":     ["connect.facebook.net/en_us/fbevents"],
        }
        analytics_found = [name for name, sigs in analytics_signatures.items() if any(s in html for s in sigs)]
        if analytics_found:
            tech["analytics"] = analytics_found

        # ── Security Headers ──
        security_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "x-xss-protection"
        ]
        present = [h for h in security_headers if h in headers]
        missing = [h for h in security_headers if h not in headers]

        security_score = int((len(present) / len(security_headers)) * 100)

        return {
            "success": True,
            "domain": domain,
            "url": resp.url,
            "status_code": resp.status_code,
            "technologies": tech,
            "security_headers": {
                "present": present,
                "missing": missing,
                "score": f"{security_score}%",
                "rating": (
                    "Excellent" if security_score >= 85 else
                    "Good"      if security_score >= 60 else
                    "Fair"      if security_score >= 40 else
                    "Poor"
                )
            }
        }

    except requests.exceptions.SSLError as e:
        return {"success": False, "error": f"SSL error: {str(e)}"}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Could not connect to the domain"}
    except Exception as e:
        return {"success": False, "error": str(e)}