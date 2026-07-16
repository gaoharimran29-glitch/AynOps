import httpx
from pydantic import BaseModel, Field

class RobotsTxtResult(BaseModel):
    domain: str = Field(description="The target domain")
    found: bool = Field(description="Whether a robots.txt file was found")
    content: str = Field(description="The raw content of the robots.txt file")
    disallowed_paths: list[str] = Field(description="List of disallowed paths")
    sitemaps: list[str] = Field(description="List of sitemaps found")
    error: str | None = Field(None, description="Error message if the request failed")

def robots_txt_inspect(domain: str) -> RobotsTxtResult:
    """Fetch and parse the robots.txt file for a given domain to find hidden paths and sitemaps."""
    url = f"https://{domain}/robots.txt"
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            response = client.get(url)
            
            if response.status_code == 200:
                content = response.text
                disallowed = []
                sitemaps = []
                
                for line in content.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            disallowed.append(path)
                    elif line.lower().startswith("sitemap:"):
                        sitemap = line.split(":", 1)[1].strip()
                        if sitemap:
                            sitemaps.append(sitemap)
                
                return RobotsTxtResult(
                    domain=domain,
                    found=True,
                    content=content,
                    disallowed_paths=list(set(disallowed)),
                    sitemaps=list(set(sitemaps))
                )
            else:
                return RobotsTxtResult(
                    domain=domain,
                    found=False,
                    content="",
                    disallowed_paths=[],
                    sitemaps=[],
                    error=f"HTTP {response.status_code}"
                )
    except Exception as e:
        return RobotsTxtResult(
            domain=domain,
            found=False,
            content="",
            disallowed_paths=[],
            sitemaps=[],
            error=str(e)
        )
