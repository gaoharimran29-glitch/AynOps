# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| Latest (main branch) | ✅ Yes |
| Older commits | ❌ No |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in this project, please report it responsibly by contacting me directly:

- **LinkedIn:** [Gaohar Imran](https://www.linkedin.com/in/gaohar-imran-5a4063379/)
- **GitHub:** Open a [private security advisory](https://github.com/gaoharimran29-glitch/AynOps/security/advisories/new)

Please include:
- A description of the vulnerability
- Steps to reproduce it
- Potential impact
- Any suggested fix if you have one

I will respond within **72 hours** and work with you to address the issue before any public disclosure.

---

## Scope

This is a **local MCP server** — it runs on the user's own machine and does not expose any network services by default.

### In scope
- Vulnerabilities in the tool logic that could lead to unintended code execution
- Input validation bypasses that could harm the user's system
- Dependency vulnerabilities with direct exploitability

### Out of scope
- Issues with third-party APIs (NVD, AbuseIPDB, WHOIS servers)
- Rate limiting or availability of external services
- Security of the user's own Claude Desktop installation

---

## Ethical Usage

This tool is intended for **authorized security research and defensive purposes only.**

Users are responsible for ensuring they have permission to scan any target domain or IP address. The maintainers are not responsible for misuse of this software.