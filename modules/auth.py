"""
ShadowScan - Auth Module
Tests authentication mechanisms: bypass, IDOR, user enumeration,
token manipulation, and privilege escalation vectors.
"""

import re
import json
from typing import List, Optional
from urllib.parse import urljoin, urlencode
from core.scanner import Scanner, ScanResponse
from core.context import ScanContext, Finding, FindingType, Severity


# Common auth bypass headers
AUTH_BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"Forwarded": "for=127.0.0.1"},
]

# IDOR numeric ID ranges to test
IDOR_TEST_IDS = [1, 2, 3, 100, 1000, 99999]

# User enumeration test usernames
TEST_USERS = ["admin", "test", "user", "administrator", "root", "support"]


class AuthModule:
    """
    Tests authentication and authorization flaws.
    """

    def __init__(self, scanner: Scanner, ctx: ScanContext):
        self.scanner = scanner
        self.ctx = ctx

    def run(self) -> List[Finding]:
        findings = []

        findings += self._test_auth_bypass()
        findings += self._test_user_enumeration()
        findings += self._test_idor()
        findings += self._test_rate_limiting()
        findings += self._analyze_jwt_tokens()

        self.ctx.mark_complete("auth")
        return findings

    def _test_auth_bypass(self) -> List[Finding]:
        """Try common auth bypass techniques on restricted endpoints."""
        findings = []

        # Get list of 403/401 endpoints to test
        restricted = [
            ep for ep in self.ctx.endpoints
            if any(k in ep.lower() for k in ["admin", "dashboard", "config", "settings"])
        ]

        # Also probe standard admin paths
        base = self.scanner.get_base_domain()
        admin_paths = ["/admin", "/api/admin", "/api/v1/admin", "/dashboard"]
        for path in admin_paths:
            url = urljoin(base, path)
            if url not in restricted:
                restricted.append(url)

        for endpoint in restricted[:10]:
            # Baseline response without bypass headers
            baseline = self.scanner.get(endpoint)
            if not baseline:
                continue

            baseline_status = baseline.status_code
            if baseline_status == 200:
                # Already accessible — flag it
                f = Finding(
                    type=FindingType.AUTH_BYPASS,
                    severity=Severity.HIGH,
                    title=f"Admin/sensitive endpoint publicly accessible",
                    url=endpoint,
                    description="Sensitive endpoint is accessible without authentication.",
                    evidence=f"HTTP {baseline_status} without auth headers",
                    module="auth",
                )
                findings.append(f)
                self.ctx.add_finding(f)
                continue

            # Try bypass headers
            for headers in AUTH_BYPASS_HEADERS:
                resp = self.scanner.get(endpoint, headers=headers)
                if not resp:
                    continue

                # Bypass detected if status changed from 403/401 to 200
                if baseline_status in (401, 403) and resp.status_code == 200:
                    header_str = ", ".join(f"{k}: {v}" for k, v in headers.items())
                    f = Finding(
                        type=FindingType.AUTH_BYPASS,
                        severity=Severity.CRITICAL,
                        title=f"Auth bypass via header manipulation",
                        url=endpoint,
                        description=f"Authentication bypassed using header: {header_str}",
                        evidence=f"Baseline: HTTP {baseline_status}\nWith headers {header_str}: HTTP {resp.status_code}",
                        module="auth",
                        metadata={"bypass_headers": headers},
                    )
                    findings.append(f)
                    self.ctx.add_finding(f)
                    break  # Found bypass, move to next endpoint

            # Try path normalization bypass
            bypass_paths = [
                endpoint + "/",
                endpoint + "/..",
                endpoint + "%2f",
                endpoint + "//",
                endpoint.replace("/admin", "/ADMIN"),
                endpoint.replace("/admin", "/%61dmin"),  # URL encoded 'a'
            ]
            for bypass_url in bypass_paths:
                resp = self.scanner.get(bypass_url)
                if resp and baseline_status in (401, 403) and resp.status_code == 200:
                    f = Finding(
                        type=FindingType.AUTH_BYPASS,
                        severity=Severity.CRITICAL,
                        title=f"Auth bypass via path normalization",
                        url=bypass_url,
                        description=f"Authentication bypassed via path manipulation.",
                        evidence=f"Original {endpoint}: HTTP {baseline_status}\nModified {bypass_url}: HTTP {resp.status_code}",
                        module="auth",
                    )
                    findings.append(f)
                    self.ctx.add_finding(f)
                    break

        return findings

    def _test_user_enumeration(self) -> List[Finding]:
        """Check if login/register endpoints leak user existence."""
        findings = []

        if not self.ctx.get_flag("has_login"):
            return findings

        login_endpoints = [
            ep for ep in self.ctx.endpoints
            if any(k in ep.lower() for k in ["login", "signin", "auth/login", "api/login"])
        ]

        for endpoint in login_endpoints[:3]:
            responses = {}

            for username in TEST_USERS:
                resp = self.scanner.post(
                    endpoint,
                    json={"username": username, "password": "SHADOWSCAN_INVALID_PASS_!@#"},
                )
                if resp:
                    responses[username] = {
                        "status": resp.status_code,
                        "body_len": resp.content_length,
                        "body": resp.body[:200],
                    }

            # Check for enumeration signals
            statuses = {v["status"] for v in responses.values()}
            lengths = {v["body_len"] for v in responses.values()}
            bodies = [v["body"] for v in responses.values()]

            # Different status codes = enumeration
            if len(statuses) > 1:
                f = Finding(
                    type=FindingType.USER_ENUMERATION,
                    severity=Severity.MEDIUM,
                    title="User enumeration via status code difference",
                    url=endpoint,
                    description="Different HTTP status codes returned for valid vs invalid usernames.",
                    evidence=f"Status codes observed: {statuses}\nResponses: {responses}",
                    module="auth",
                )
                findings.append(f)
                self.ctx.add_finding(f)

            # Check for explicit "user not found" vs "wrong password"
            elif any("not found" in b.lower() or "does not exist" in b.lower() for b in bodies):
                f = Finding(
                    type=FindingType.USER_ENUMERATION,
                    severity=Severity.MEDIUM,
                    title="User enumeration via error message",
                    url=endpoint,
                    description="Application reveals whether a username exists via error message.",
                    evidence=f"Error messages: {bodies[:2]}",
                    module="auth",
                )
                findings.append(f)
                self.ctx.add_finding(f)

        return findings

    def _test_idor(self) -> List[Finding]:
        """Test for IDOR on endpoints containing numeric IDs."""
        findings = []

        # Find endpoints with numeric IDs
        id_pattern = re.compile(r"/(\d+)(/|$|\?)")
        idor_candidates = []

        for endpoint in self.ctx.endpoints:
            if id_pattern.search(endpoint):
                idor_candidates.append(endpoint)

        # Also generate common IDOR paths
        base = self.scanner.get_base_domain()
        for id_val in IDOR_TEST_IDS:
            for path_template in [
                f"/api/user/{id_val}",
                f"/api/v1/users/{id_val}",
                f"/api/account/{id_val}",
                f"/api/order/{id_val}",
                f"/user/{id_val}",
                f"/profile/{id_val}",
            ]:
                url = urljoin(base, path_template)
                idor_candidates.append(url)

        seen_data = {}

        for endpoint in idor_candidates[:20]:
            resp = self.scanner.get(endpoint)
            if not resp or resp.status_code not in (200,):
                continue

            if resp.is_json():
                # Check if response contains user data
                body_lower = resp.body.lower()
                data_indicators = ["email", "phone", "name", "address", "user_id", "account"]

                if any(indicator in body_lower for indicator in data_indicators):
                    # Compare with a different ID
                    alt_url = id_pattern.sub(lambda m: m.group(0).replace(m.group(1), str(int(m.group(1)) + 1)), endpoint)
                    alt_resp = self.scanner.get(alt_url)

                    if alt_resp and alt_resp.status_code == 200 and alt_resp.body != resp.body:
                        f = Finding(
                            type=FindingType.IDOR,
                            severity=Severity.HIGH,
                            title=f"IDOR — object-level access control missing",
                            url=endpoint,
                            description="Different user data returned for sequential IDs without authentication. Insecure Direct Object Reference confirmed.",
                            evidence=f"ID {endpoint}: {resp.body[:200]}\nID {alt_url}: {alt_resp.body[:200]}",
                            module="auth",
                            metadata={"endpoint_pattern": endpoint},
                        )
                        findings.append(f)
                        self.ctx.add_finding(f)
                        self.ctx.set_flag("has_idor_candidate", True)

        return findings

    def _test_rate_limiting(self) -> List[Finding]:
        """Check if login endpoints have rate limiting."""
        findings = []

        if not self.ctx.get_flag("has_login"):
            return findings

        login_endpoints = [
            ep for ep in self.ctx.endpoints
            if "login" in ep.lower() or "signin" in ep.lower()
        ]

        for endpoint in login_endpoints[:2]:
            # Fire 10 rapid requests
            responses = []
            for i in range(10):
                resp = self.scanner.post(
                    endpoint,
                    json={"username": f"shadowtest{i}", "password": "wrongpassword"},
                )
                if resp:
                    responses.append(resp.status_code)

            # If we never got 429 or increasing delays, no rate limit
            if responses and 429 not in responses and all(s in (200, 400, 401, 403) for s in responses):
                f = Finding(
                    type=FindingType.RATE_LIMIT_MISSING,
                    severity=Severity.MEDIUM,
                    title="No rate limiting on login endpoint",
                    url=endpoint,
                    description="Login endpoint does not enforce rate limiting. Brute-force attacks are viable.",
                    evidence=f"10 rapid requests — all returned: {set(responses)}. No 429 observed.",
                    module="auth",
                )
                findings.append(f)
                self.ctx.add_finding(f)

        return findings

    def _analyze_jwt_tokens(self) -> List[Finding]:
        """If JWTs found, check for common vulnerabilities."""
        findings = []

        if not self.ctx.get_flag("jwt_found"):
            return findings

        # Find JWTs in existing findings
        jwt_pattern = re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")
        jwts_found = []

        for finding in self.ctx.findings:
            matches = jwt_pattern.findall(finding.evidence or "")
            jwts_found.extend(matches)

        for jwt in jwts_found[:3]:
            parts = jwt.split(".")
            if len(parts) != 3:
                continue

            try:
                import base64
                # Decode header (add padding)
                header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))
                alg = header.get("alg", "")

                # Check for 'none' algorithm
                if alg.lower() == "none":
                    f = Finding(
                        type=FindingType.TOKEN_EXPOSED,
                        severity=Severity.CRITICAL,
                        title="JWT with 'none' algorithm",
                        url=self.scanner.base_url,
                        description="JWT uses 'none' algorithm — signatures not verified. Full token forgery possible.",
                        evidence=f"JWT header: {header}",
                        module="auth",
                    )
                    findings.append(f)
                    self.ctx.add_finding(f)

                # Check for weak algorithms
                elif alg in ("HS256", "HS384", "HS512"):
                    f = Finding(
                        type=FindingType.TOKEN_EXPOSED,
                        severity=Severity.LOW,
                        title=f"JWT uses symmetric algorithm ({alg})",
                        url=self.scanner.base_url,
                        description=f"JWT uses {alg}. If the secret key is weak, JWT can be cracked offline.",
                        evidence=f"JWT header: {header}\nToken: {jwt[:50]}...",
                        module="auth",
                        metadata={"algorithm": alg, "token_snippet": jwt[:60]},
                    )
                    findings.append(f)
                    self.ctx.add_finding(f)

            except Exception:
                pass

        return findings
