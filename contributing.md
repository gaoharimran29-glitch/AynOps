# Contributing to AynOps

Thanks for your interest in contributing! This project is actively growing and new tools are welcome. Every contribution — whether a new tool, bug fix, or documentation improvement — is appreciated.

---

## How to Add a New Tool

### 1. Create a New Tool

Add a new file inside the `tools/` directory:

```
tools/
└── my_tool.py
```

Implement your tool using the standard pattern:

```python
from utils.helpers import is_valid_domain

def your_tool_name(domain: str) -> dict:
    """
    One clear sentence describing what this tool does.
    """
    try:
        if not is_valid_domain(domain):
            return {"success": False, "error": "Invalid domain format"}

        result = {}

        return {
            "success": True,
            "domain": domain,
            # additional fields
        }

    except Exception as e:
        return {"success": False, "error": str(e)}
```

For tools that operate on IP addresses, validate using Python's built-in `ipaddress` module:

```python
import ipaddress

try:
    ip = str(ipaddress.ip_address(ip_address.strip()))
except ValueError:
    return {"success": False, "error": "Invalid IP address format"}
```

---

### 2. Register the Tool

Import and register the tool in `server.py`:

```python
from tools.file_name import tool_name

mcp.tool()(tool_name)
```

---

### 3. Add Tests

Create a corresponding test file inside the `tests/` directory:

```
tests/
└── test_my_tool.py
```

Run the tests:

```bash
pytest tests/test_my_tool.py -v
```
All tests should pass wihtout any warning or error.

Every new tool must include at least:

- One **happy-path** test (valid input, expected output)
- One **failure-path** test (invalid input or error handling)

---

### 4. Verify with MCP Inspector

Test the tool using MCP Inspector:

```bash
fastmcp dev inspector server.py
```

Verify that:

- The tool appears in the available tools list
- Inputs are validated correctly
- Expected results are returned
- Error handling works as intended

---

### 5. Update Documentation & `mcp.json`

- Add the tool to the tools table in `README.md`
- Add the relevant info in `mcp.json`
- If the tool requires an API key, document how to obtain and configure it in the README & mcp.json

---

### 6. Update `.env.example` and `requirements.txt` (If Applicable)

If your tool requires new environment variables, add them to `.env.example` with placeholder values:

```env
SHODAN_API_KEY=your_api_key_here
VIRUSTOTAL_API_KEY=your_api_key_here
```

> **Never** commit real API keys, secrets, or credentials to the repository.

---

### 7. Submit Your Changes

Open a pull request and submit the changes

## Steps to Contribute

1. Fork the repo
2. Create a branch:
   ```bash
   git checkout -b tool/your-tool-name
   ```
3. Add your tool to `tools/` following the pattern above
4. Test it in the MCP Inspector:
   ```bash
   fastmcp dev inspector server.py
   ```
5. Add unit test for tool in `tests/`.
6. Update the tools table in `README.md`
7. Update the relevant info in `mcp.json`
8. Update `requirements.txt` if you added a new dependency
9. Update `.env.example` if your tool needs an API key
10. Open a pull request with a short description

---

## PR Checklist

- [ ] Tool follows the existing pattern in `tools/`
- [ ] Input is validated (`is_valid_domain()` or `ipaddress` module)
- [ ] Returns `{"success": True/False, ...}` on all code paths
- [ ] Exceptions handled with `try/except` — server must never crash
- [ ] Unit test added in `tests/`.
- [ ] Dependencies are minimal — reuse existing libraries where possible
- [ ] Tools table updated in `README.md`
- [ ] `mcp.json` updated if applicable
- [ ] `requirements.txt` updated if a new dependency was added
- [ ] `.env.example` updated if a new API key is required

---

## Guidelines

| Rule | Detail |
|---|---|
| **Consistency** | Every tool returns `{"success": True/False, ...}` |
| **Validation** | Always validate inputs before making external calls |
| **Error handling** | Catch exceptions and return `{"success": False, "error": str(e)}` |
| **Dependencies** | Check if a library is already used before adding a new one |
| **Legal** | Use `scanme.nmap.org` for port scanning tests — the only public host officially permitted for Nmap testing |
| **API keys** | Never hardcode keys; always use `os.getenv("YOUR_API_KEY")` |

---

## Questions?

Open an issue on GitHub or reach out on LinkedIn: [Gaohar Imran](https://www.linkedin.com/in/gaohar-imran-5a4063379/)