# Contributing to AynOps

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

Pick one issue and open a PR:

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
   fastmcp dev inspector main.py
   ```
6. Update the tools table in `README.md`
7. Update `requirements.txt` if you added a new dependency
8. Update '.env.example' if any tool needs an api key
8. Open a pull request with a short description

---

## ✅ PR Checklist

Before submitting make sure:

- [ ] Tool follows the existing pattern in `main.py`
- [ ] Input is validated (`is_valid_domain()` or `ipaddress` module)
- [ ] Returns `{"success": True/False, ...}` on all code paths
- [ ] Exceptions handled with `try/except` — server must never crash
- [ ] Dependencies minimal — reuse existing libraries where possible
- [ ] Tools table updated in `README.md`
- [ ] `requirements.txt` updated if new dependency added
- [ ] `.env.example` updated if needed

---

## 📏 Guidelines

- **Consistency** — every tool returns `{"success": True/False, ...}`
- **Validation** — always validate inputs before making any external calls
- **Error handling** — catch exceptions and return `{"success": False, "error": str(e)}`
- **Dependencies** — check if a library is already used before adding a new one
- **Legal** — use `scanme.nmap.org` for port scanning tests — the only public host officially permitted for Nmap testing
- **API keys** — never hardcode keys; use environment variables like `os.getenv("YOUR_API_KEY")`

---

## ❓ Questions?

Open an issue on GitHub or reach out on LinkedIn:
[Gaohar Imran](https://www.linkedin.com/in/gaohar-imran-5a4063379/)
