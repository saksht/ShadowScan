"""
ShadowScan - Recon Module
Endpoint discovery, technology fingerprinting, and attack surface mapping.
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse
from core.scanner import Scanner, ScanResponse
from core.context import ScanContext, Finding, FindingType, Severity


# Common paths to probe
COMMON_PATHS = [
    "/", "/api", "/api/v1", "/api/v2", "/api/v3",
    "/admin", "/administrator", "/wp-admin", "/dashboard",
    "/login", "/signin", "/auth", "/oauth",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/api/docs", "/api/swagger", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql", "/.graphql",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/config", "/configuration", "/settings",
    "/.env", "/.git/HEAD", "/.git/config",
    "/backup", "/backup.zip", "/db.sql",
    "/phpinfo.php", "/info.php", "/test.php",
    "/health", "/healthz", "/ping", "/status",
    "/metrics", "/actuator", "/actuator/env", "/actuator/mappings",
    "/v1", "/v2", "/v3",
    "/user", "/users", "/account", "/accounts",
    "/profile", "/me", "/self",
    "/upload", "/uploads", "/files",
    "/debug", "/trace",
]

# Technology fingerprints
TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wp-login"],
    "Drupal": ["sites/default", "drupal"],
    "Laravel": ["laravel_session", "X-Powered-By: PHP"],
    "Django": ["csrfmiddlewaretoken", "__django"],
    "Spring Boot": ["X-Application-Context", "Whitelabel Error Page"],
    "Express.js": ["X-Powered-By: Express"],
    "GraphQL": ["graphql", "GraphQL", "__schema"],
    "Swagger": ["swagger-ui", "swagger.json", "openapi"],
    "AWS S3": ["AmazonS3", "x-amz-"],
    "Cloudflare": ["CF-RAY", "cf-request-id"],
    "nginx": ["Server: nginx"],
    "Apache": ["Server: Apache"],
    "PHP": ["X-Powered-By: PHP", ".php"],
    "ASP.NET": ["X-Powered-By: ASP.NET", "ASP.NET_SessionId"],
    "Next.js": ["__NEXT_DATA__", "x-nextjs"],
    "React": ["__REACT_ROOT__", "react-root"],
}


class ReconModule:
    """
    First module to run. Maps the attack surface.
    Finds endpoints, detects technologies, seeds the context
    for all subsequent modules.
    """

    def __init__(self, scanner: Scanner, ctx: ScanContext):
        self.scanner = scanner
        self.ctx = ctx

    def run(self) -> List[Finding]:
        findings = []

        # 1. Probe common paths
        findings += self._probe_paths()

        # 2. Parse discovered pages for more links
        findings += self._crawl_discovered()

        # 3. Fingerprint technologies
        findings += self._fingerprint_tech()

        # 4. Check for API documentation
        findings += self._check_api_docs()

        self.ctx.mark_complete("recon")
        return findings

    def _probe_paths(self) -> List[Finding]:
        findings = []
        base = self.scanner.get_base_domain()

        for path in COMMON_PATHS:
            url = urljoin(base, path)
            resp = self.scanner.get(url)
            if not resp:
                continue

            if resp.status_code in (200, 301, 302, 403):
                self.ctx.add_endpoint(url)

                # Flag interesting endpoints
                if resp.status_code == 200:
                    finding = self._classify_endpoint(url, path, resp)
                    if finding:
                        findings.append(finding)
                        self.ctx.add_finding(finding)

                elif resp.status_code == 403:
                    # 403 = exists but forbidden → worth flagging
                    f = Finding(
                        type=FindingType.SENSITIVE_ENDPOINT,
                        severity=Severity.LOW,
                        title=f"Restricted endpoint: {path}",
                        url=url,
                        description=f"Endpoint returns 403 — exists but access controlled. May be bypassable.",
                        evidence=f"HTTP 403 on {url}",
                        module="recon",
                    )
                    findings.append(f)
                    self.ctx.add_finding(f)

        return findings

    def _classify_endpoint(
        self, url: str, path: str, resp: ScanResponse
    ) -> Optional[Finding]:
        """Classify a 200-response endpoint by type."""

        # API docs — high value
        if any(k in path for k in ["/swagger", "/api-docs", "/openapi", "/graphiql"]):
            self.ctx.set_flag("has_api", True)
            return Finding(
                type=FindingType.SENSITIVE_ENDPOINT,
                severity=Severity.MEDIUM,
                title=f"API documentation exposed: {path}",
                url=url,
                description="API documentation is publicly accessible. Reveals all endpoints, parameters, and auth methods.",
                evidence=f"HTTP 200 on {url}",
                module="recon",
                metadata={"path": path},
            )

        # Login endpoints
        if any(k in path for k in ["/login", "/signin", "/auth"]):
            self.ctx.set_flag("has_login", True)
            return Finding(
                type=FindingType.ENDPOINT_DISCOVERED,
                severity=Severity.INFO,
                title=f"Login endpoint: {path}",
                url=url,
                description="Authentication endpoint discovered.",
                evidence=f"HTTP 200 on {url}",
                module="recon",
            )

        # Admin panels
        if any(k in path for k in ["/admin", "/dashboard", "/administrator"]):
            self.ctx.set_flag("has_login", True)
            return Finding(
                type=FindingType.SENSITIVE_ENDPOINT,
                severity=Severity.HIGH,
                title=f"Admin panel accessible: {path}",
                url=url,
                description="Admin/dashboard endpoint is publicly reachable.",
                evidence=f"HTTP 200 on {url}",
                module="recon",
            )

        # GraphQL
        if "graphql" in path.lower():
            self.ctx.set_flag("has_graphql", True)
            if "graphql" not in self.ctx.technologies:
                self.ctx.technologies.append("GraphQL")

        # Git exposure
        if ".git" in path:
            return Finding(
                type=FindingType.SECRET_EXPOSED,
                severity=Severity.CRITICAL,
                title=".git directory exposed",
                url=url,
                description="Git repository is publicly accessible. Source code and secrets may be extractable.",
                evidence=f"HTTP 200 on {url}, content: {resp.body[:100]}",
                module="recon",
            )

        # .env file
        if ".env" in path:
            return Finding(
                type=FindingType.SECRET_EXPOSED,
                severity=Severity.CRITICAL,
                title=".env file exposed",
                url=url,
                description="Environment file is publicly readable. Likely contains credentials, API keys, DB passwords.",
                evidence=f"HTTP 200 on {url}\nContent snippet: {resp.body[:200]}",
                module="recon",
            )

        # Spring Boot actuator
        if "actuator" in path:
            return Finding(
                type=FindingType.SENSITIVE_ENDPOINT,
                severity=Severity.HIGH,
                title=f"Spring Boot actuator exposed: {path}",
                url=url,
                description="Actuator endpoint exposes internal app state, environment variables, and mappings.",
                evidence=f"HTTP 200 on {url}",
                module="recon",
            )

        return None

    def _crawl_discovered(self) -> List[Finding]:
        """Extract links from already-discovered pages."""
        findings = []
        base_domain = urlparse(self.scanner.base_url).netloc

        for endpoint in list(self.ctx.endpoints)[:10]:  # limit crawl
            resp = self.scanner.get(endpoint)
            if not resp or not resp.body:
                continue

            # Extract href links
            links = re.findall(r'href=["\']([^"\']+)["\']', resp.body)
            for link in links:
                if link.startswith(("http", "/")):
                    parsed = urlparse(link)
                    if parsed.netloc == base_domain or not parsed.netloc:
                        full_url = urljoin(self.scanner.base_url, link)
                        self.ctx.add_endpoint(full_url)

            # Extract API paths from JS
            api_paths = re.findall(r'["\'](/api/[^"\']+)["\']', resp.body)
            for path in api_paths:
                url = urljoin(self.scanner.base_url, path)
                if url not in self.ctx.endpoints:
                    self.ctx.add_endpoint(url)
                    self.ctx.set_flag("has_api", True)

        return findings

    def _fingerprint_tech(self) -> List[Finding]:
        """Detect technologies from responses."""
        findings = []
        base = self.scanner.get_base_domain()
        resp = self.scanner.get(base)
        if not resp:
            return findings

        combined = resp.body + " " + " ".join(
            f"{k}: {v}" for k, v in resp.headers.items()
        )

        for tech, signatures in TECH_SIGNATURES.items():
            if any(sig.lower() in combined.lower() for sig in signatures):
                if tech not in self.ctx.technologies:
                    self.ctx.technologies.append(tech)
                    findings.append(Finding(
                        type=FindingType.TECH_DETECTED,
                        severity=Severity.INFO,
                        title=f"Technology detected: {tech}",
                        url=base,
                        description=f"{tech} identified via response signatures.",
                        evidence=f"Matched signatures for {tech}",
                        module="recon",
                        metadata={"technology": tech},
                    ))

        return findings

    def _check_api_docs(self) -> List[Finding]:
        """Try to fetch and parse OpenAPI/Swagger spec."""
        findings = []
        spec_paths = ["/openapi.json", "/swagger.json", "/api/swagger.json", "/v2/api-docs"]

        for path in spec_paths:
            url = urljoin(self.scanner.get_base_domain(), path)
            resp = self.scanner.get(url)
            if not resp or resp.status_code != 200:
                continue

            if resp.is_json():
                # Extract paths from OpenAPI spec
                try:
                    import json
                    spec = json.loads(resp.body)
                    paths = spec.get("paths", {})
                    for api_path in paths:
                        full_url = urljoin(self.scanner.get_base_domain(), api_path)
                        self.ctx.add_endpoint(full_url)

                    findings.append(Finding(
                        type=FindingType.SENSITIVE_ENDPOINT,
                        severity=Severity.MEDIUM,
                        title=f"OpenAPI spec accessible: {path}",
                        url=url,
                        description=f"OpenAPI specification exposed {len(paths)} endpoints.",
                        evidence=f"Parsed {len(paths)} API paths from {url}",
                        module="recon",
                        metadata={"endpoint_count": len(paths)},
                    ))
                    self.ctx.set_flag("has_api", True)
                except Exception:
                    pass

        return findings
