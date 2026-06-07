"""
ShadowScan - Exposure Module
Detects exposed secrets, API keys, tokens, and sensitive data leaks.
Based on real patterns from bug bounty experience (Sentry DSN, Mixpanel, etc.)
"""

import re
from typing import List
from urllib.parse import urljoin
from core.scanner import Scanner, ScanResponse
from core.context import ScanContext, Finding, FindingType, Severity


# Regex patterns for secret detection
SECRET_PATTERNS = {
    "AWS Access Key": (r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
    "AWS Secret Key": (r"[Aa]ws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", Severity.CRITICAL),
    "Sentry DSN": (r"https://[0-9a-f]{32}@[a-z0-9.]+/[0-9]+", Severity.HIGH),
    "Sentry DSN (Public Key)": (r"['\"][0-9a-f]{32}['\"].*sentry", Severity.HIGH),
    "Mixpanel Token": (r"mixpanel\.init\(['\"]([a-f0-9]{32})['\"]", Severity.MEDIUM),
    "Google API Key": (r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH),
    "Google OAuth Client": (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", Severity.MEDIUM),
    "Stripe Secret Key": (r"sk_live_[0-9a-zA-Z]{24}", Severity.CRITICAL),
    "Stripe Publishable Key": (r"pk_live_[0-9a-zA-Z]{24}", Severity.LOW),
    "Slack Token": (r"xox[baprs]-[0-9A-Za-z\-]+", Severity.HIGH),
    "Slack Webhook": (r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+", Severity.HIGH),
    "GitHub Token": (r"ghp_[0-9a-zA-Z]{36}", Severity.CRITICAL),
    "GitHub Token (old)": (r"['\"][0-9a-f]{40}['\"].*git", Severity.HIGH),
    "JWT Token": (r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", Severity.MEDIUM),
    "Bearer Token": (r"[Bb]earer\s+([a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)", Severity.HIGH),
    "Firebase URL": (r"https://[a-z0-9-]+\.firebaseio\.com", Severity.MEDIUM),
    "Firebase API Key": (r"AIza[0-9A-Za-z\\-_]{35}", Severity.HIGH),
    "Twilio Account SID": (r"AC[a-z0-9]{32}", Severity.HIGH),
    "Twilio Auth Token": (r"[Tt]wilio.{0,20}['\"][0-9a-f]{32}['\"]", Severity.CRITICAL),
    "SendGrid API Key": (r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}", Severity.HIGH),
    "Mailgun API Key": (r"key-[0-9a-zA-Z]{32}", Severity.HIGH),
    "HubSpot API Key": (r"[Hh]ub[Ss]pot.{0,20}['\"][0-9a-f-]{36}['\"]", Severity.HIGH),
    "Private Key": (r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", Severity.CRITICAL),
    "Password in URL": (r"[Pp]assword[=:]\s*[^\s&\"']{6,}", Severity.HIGH),
    "DB Connection String": (r"(mysql|postgresql|mongodb|redis)://[^@\s]+@[^\s\"']+", Severity.CRITICAL),
    "Internal IP": (r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", Severity.LOW),
}

# JS files to scan for secrets
JS_PATHS = [
    "/main.js", "/app.js", "/bundle.js",
    "/static/js/main.chunk.js", "/static/js/bundle.js",
    "/assets/app.js", "/js/app.js",
]

# Headers that indicate security misconfiguration
MISSING_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
]


class ExposureModule:
    """
    Scans for exposed secrets, API keys, tokens, and misconfigurations.
    Covers JS files, response bodies, headers, and error messages.
    """

    def __init__(self, scanner: Scanner, ctx: ScanContext):
        self.scanner = scanner
        self.ctx = ctx

    def run(self) -> List[Finding]:
        findings = []

        findings += self._scan_js_files()
        findings += self._scan_endpoints_for_secrets()
        findings += self._check_security_headers()
        findings += self._check_error_disclosure()
        findings += self._check_cors_misconfig()

        self.ctx.mark_complete("exposure")
        return findings

    def _scan_js_files(self) -> List[Finding]:
        """Scan JavaScript files for hardcoded secrets."""
        findings = []
        base = self.scanner.get_base_domain()

        for path in JS_PATHS:
            url = urljoin(base, path)
            resp = self.scanner.get(url)
            if not resp or resp.status_code != 200:
                continue

            file_findings = self._scan_content_for_secrets(resp.body, url, "js_file")
            findings += file_findings

        # Also scan any JS files found during recon
        for endpoint in self.ctx.endpoints:
            if endpoint.endswith(".js") and endpoint not in [urljoin(base, p) for p in JS_PATHS]:
                resp = self.scanner.get(endpoint)
                if resp and resp.status_code == 200:
                    findings += self._scan_content_for_secrets(resp.body, endpoint, "js_file")

        return findings

    def _scan_endpoints_for_secrets(self) -> List[Finding]:
        """Scan all discovered endpoints for secret exposure."""
        findings = []

        for endpoint in list(self.ctx.endpoints)[:30]:
            resp = self.scanner.get(endpoint)
            if not resp or resp.status_code not in (200, 403):
                continue
            findings += self._scan_content_for_secrets(resp.body, endpoint, "endpoint_scan")

        return findings

    def _scan_content_for_secrets(
        self, content: str, url: str, source: str
    ) -> List[Finding]:
        """Run all secret patterns against content."""
        findings = []

        for secret_type, (pattern, severity) in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if not matches:
                continue

            # Deduplicate
            unique_matches = list(set(str(m) for m in matches))
            evidence = f"Pattern: {secret_type}\nMatches found: {unique_matches[:3]}"

            # Set context flags
            if "JWT" in secret_type:
                self.ctx.set_flag("jwt_found", True)
                self.ctx.set_flag("has_auth_token", True)
            if severity in (Severity.CRITICAL, Severity.HIGH):
                self.ctx.set_flag("secret_found", True)

            f = Finding(
                type=FindingType.SECRET_EXPOSED if "Token" not in secret_type else FindingType.TOKEN_EXPOSED,
                severity=severity,
                title=f"{secret_type} exposed in {source}",
                url=url,
                description=f"{secret_type} found in {source}. This may allow unauthorized access.",
                evidence=evidence,
                module="exposure",
                metadata={
                    "secret_type": secret_type,
                    "source": source,
                    "match_count": len(unique_matches),
                },
            )
            findings.append(f)
            self.ctx.add_finding(f)

        return findings

    def _check_security_headers(self) -> List[Finding]:
        """Check for missing security headers."""
        findings = []
        resp = self.scanner.get(self.scanner.base_url)
        if not resp:
            return findings

        missing = [h for h in MISSING_SECURITY_HEADERS if not resp.header_exists(h)]

        if missing:
            findings.append(Finding(
                type=FindingType.ERROR_DISCLOSURE,
                severity=Severity.LOW,
                title=f"Missing security headers ({len(missing)})",
                url=self.scanner.base_url,
                description=f"Security headers missing: {', '.join(missing)}",
                evidence=f"Headers not found in response: {missing}",
                module="exposure",
                metadata={"missing_headers": missing},
            ))
            self.ctx.add_finding(findings[-1])

        return findings

    def _check_error_disclosure(self) -> List[Finding]:
        """Trigger errors and check for stack traces / tech disclosure."""
        findings = []
        base = self.scanner.get_base_domain()

        # Send malformed requests to trigger errors
        probe_urls = [
            urljoin(base, "/api/SHADOWSCAN_PROBE_404_TEST"),
            urljoin(base, "/api/v1/SHADOWSCAN_PROBE_404_TEST"),
            urljoin(base, "/'OR'1'='1"),
        ]

        error_patterns = [
            (r"(Traceback \(most recent call last\))", "Python traceback"),
            (r"(at .+ \(.+\.js:\d+:\d+\))", "Node.js stack trace"),
            (r"(java\..+Exception)", "Java exception"),
            (r"(System\.Web\.HttpException)", "ASP.NET exception"),
            (r"(Fatal error:.*PHP)", "PHP fatal error"),
            (r"(Microsoft OLE DB|SQL Server.*Error)", "MSSQL error"),
            (r"(You have an error in your SQL syntax)", "MySQL error"),
            (r"(ORA-\d{5})", "Oracle DB error"),
            (r"(pg_query\(\))", "PostgreSQL error"),
        ]

        for url in probe_urls:
            resp = self.scanner.get(url)
            if not resp:
                continue

            for pattern, error_type in error_patterns:
                if re.search(pattern, resp.body):
                    f = Finding(
                        type=FindingType.ERROR_DISCLOSURE,
                        severity=Severity.MEDIUM,
                        title=f"Error disclosure: {error_type}",
                        url=url,
                        description=f"Application returns {error_type} in response. Reveals internal tech stack.",
                        evidence=f"Error pattern matched in response to: {url}\nSnippet: {resp.body[:300]}",
                        module="exposure",
                        metadata={"error_type": error_type},
                    )
                    findings.append(f)
                    self.ctx.add_finding(f)
                    break

        return findings

    def _check_cors_misconfig(self) -> List[Finding]:
        """Test for CORS misconfiguration."""
        findings = []
        resp = self.scanner.get(
            self.scanner.base_url,
            headers={"Origin": "https://evil.shadowscan.io"},
        )
        if not resp:
            return findings

        acao = resp.get_header("Access-Control-Allow-Origin")
        acac = resp.get_header("Access-Control-Allow-Credentials")

        if acao == "https://evil.shadowscan.io":
            severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
            f = Finding(
                type=FindingType.WEAK_AUTH,
                severity=severity,
                title="CORS misconfiguration — arbitrary origin reflected",
                url=self.scanner.base_url,
                description=(
                    "Server reflects arbitrary Origin in ACAO header. "
                    + ("With credentials allowed — full account takeover possible." if acac == "true" else "")
                ),
                evidence=f"Origin: evil.shadowscan.io\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                module="exposure",
            )
            findings.append(f)
            self.ctx.add_finding(f)

        elif acao == "*" and acac == "true":
            f = Finding(
                type=FindingType.WEAK_AUTH,
                severity=Severity.MEDIUM,
                title="CORS: wildcard origin with credentials",
                url=self.scanner.base_url,
                description="Wildcard ACAO with credentials is a browser-blocked but misconfigured CORS policy.",
                evidence=f"ACAO: * with ACAC: true",
                module="exposure",
            )
            findings.append(f)
            self.ctx.add_finding(f)

        return findings
