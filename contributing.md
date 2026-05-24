# Contributing to CyberSecurity MCP Server

Thanks for your interest in contributing! This project is actively growing and new tools are welcome. Every contribution — whether a new tool, bug fix, or documentation improvement — is appreciated.

---

## 🛠️ How to Add a New Tool

Adding a tool takes about 30-50 lines of Python. Here's the pattern every tool follows:

```python
@mcp.tool()
def your_tool_name(domain: str) -> dict:
    """
    One clear sentence describing what this tool does.
    """
    try:
        # 1. Validate input
        if not is_valid_domain(domain):
            return {"success": False, "error": "Invalid domain format"}

        # 2. Your logic here
        result = {}

        # 3. Return consistent structure
        return {
            "success": True,
            "domain": domain,
            # your fields here
        }

    except Exception as e:
        return {"success": False, "error": str(e)}
```

For tools that take an IP instead of a domain, validate using Python's built-in:

```python
import ipaddress

try:
    ip = str(ipaddress.ip_address(ip_address.strip()))
except ValueError:
    return {"success": False, "error": "Invalid IP address format"}
```

---

## 💡 Tool Ideas (open for contribution)

Pick one and open a PR:

- [ ] **Shodan Integration** — internet-wide device and service search
- [ ] **Certificate Transparency** — search cert logs for subdomains via crt.sh
- [ ] **HTTP Headers Analyzer** — deep analysis of all response headers
- [ ] **Phishing Detector** — score domains for phishing likelihood
- [ ] **Reverse DNS Lookup** — resolve IPs back to hostnames
- [ ] **ASN Lookup** — find Autonomous System Number and org for an IP
- [ ] **Email Security Check** — validate SPF, DKIM, DMARC records

---

## 📋 Steps to Contribute

1. Fork the repo
2. Create a branch:
   ```bash
   git checkout -b tool/your-tool-name
   ```
3. Add your tool to `main.py` following the pattern above
4. Test it in the MCP inspector:
   ```bash
   fastmcp inspector main.py
   ```
5. Add tests to `test_security_tools.py` — mock external APIs so tests don't need live connections
6. Update the tools table in `README.md`
7. Update `requirements.txt` if you added a new dependency
8. Open a pull request with a short description

---

## ✅ PR Checklist

Before submitting make sure:

- [ ] Tool follows the existing pattern in `main.py`
- [ ] Input is validated (`is_valid_domain()` or `ipaddress` module)
- [ ] Returns `{"success": True/False, ...}` on all code paths
- [ ] Exceptions handled with `try/except` — server must never crash
- [ ] Dependencies minimal — reuse existing libraries where possible
- [ ] Tests added to `test_security_tools.py` with mocked APIs
- [ ] Tools table updated in `README.md`
- [ ] `requirements.txt` updated if new dependency added

---

## 📏 Guidelines

- **Consistency** — every tool returns `{"success": True/False, ...}`
- **Validation** — always validate inputs before making any external calls
- **Error handling** — catch exceptions and return `{"success": False, "error": str(e)}`
- **Dependencies** — check if a library is already used before adding a new one
- **Legal** — use `scanme.nmap.org` for port scanning tests — the only public host officially permitted for Nmap testing
- **API keys** — never hardcode keys; use environment variables like `os.getenv("YOUR_API_KEY")`

---

## 🧪 Running Tests

```bash
python -m unittest test_security_tools.py
```

All tests should pass before opening a PR. Tests use mocked APIs so no internet or API keys are needed.

---

## ❓ Questions?

Open an issue on GitHub or reach out on LinkedIn:
[Gaohar Imran](https://www.linkedin.com/in/gaohar-imran-5a4063379/)
