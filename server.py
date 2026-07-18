from fastmcp import FastMCP
from fastmcp.prompts import PromptResult

from tools.whois_tool import whois_lookup
from tools.dns_tool import dns_enumeration
from tools.portscan_tool import port_scan
from tools.ssl_tool import ssl_inspect
from tools.techstack_tool import tech_stack_detect
from tools.asn_tool import asn_lookup
from tools.fullrecon_tool import full_recon
from tools.cve_tool import cve_lookup
from tools.iprep_tool import ip_reputation
from tools.crt_sh_tool import cert_transparency
from tools.headers_tool import headers_analyzer
from tools.email_security_tool import email_security_check
from tools.redirect_tracer import trace_redirects
from tools.cloud_exposure_tool import cloud_exposure_check
from tools.robots_txt_tool import robots_txt_inspect
from tools.prompts.threat_analysis import THREAT_ANALYSIS_PROMPT

mcp = FastMCP("AynOps")

mcp.tool()(whois_lookup)
mcp.tool()(dns_enumeration)
mcp.tool()(port_scan)
mcp.tool()(ssl_inspect)
mcp.tool()(tech_stack_detect)
mcp.tool()(asn_lookup)
mcp.tool()(full_recon)
mcp.tool()(cve_lookup)
mcp.tool()(ip_reputation)
mcp.tool()(cert_transparency)
mcp.tool()(headers_analyzer)
mcp.tool()(email_security_check)
mcp.tool()(trace_redirects)
mcp.tool()(cloud_exposure_check)
mcp.tool()(robots_txt_inspect)

@mcp.prompt(
    name="threat_analysis",
    description="Generate a structured cybersecurity threat analysis from AynOps full reconnaissance results.",
    tags={"security", "analysis", "full_recon", "threat_intelligence"},
    meta={"tool": "full_recon", "category": "security_analysis",}
)
def threat_analysis() -> PromptResult:
    """
    Generate a threat analysis prompt for the `full_recon` tool.
    """
    return PromptResult(
        messages=THREAT_ANALYSIS_PROMPT,
        description="Threat analysis prompt for AynOps full reconnaissance results.",
        meta={"tool": "full_recon",}
    )

if __name__ == "__main__":
    mcp.run()