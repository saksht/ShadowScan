"""
ShadowScan - API Module
Tests REST and GraphQL APIs for common vulnerabilities:
unauthenticated access, introspection, mass assignment, injection.
"""

import json
import re
from typing import List, Optional, Dict
from urllib.parse import urljoin
from core.scanner import Scanner, ScanResponse
from core.context import ScanContext, Finding, FindingType, Severity


# GraphQL introspection query
GRAPHQL_INTROSPECTION = """
{
  __schema {
    types {
      name
      fields {
        name
        args { name type { name kind } }
      }
    }
  }
}
"""

# Common REST API paths to probe
REST_API_PATHS = [
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/accounts", "/api/v1/accounts",
    "/api/admin/users", "/api/admin",
    "/api/config", "/api/settings",
    "/api/debug", "/api/internal",
    "/api/keys", "/api/tokens",
    "/api/export", "/api/dump",
    "/api/backup",
    "/api/metrics", "/api/stats",
]

# Mass assignment test fields
PRIVILEGED_FIELDS = [
    "is_admin", "role", "admin", "is_staff", "is_superuser",
    "permissions", "scope", "privilege", "account_type",
    "verified", "trusted", "internal",
]


class APIModule:
    """
    Tests API-specific vulnerabilities across REST and GraphQL.
    """

    def __init__(self, scanner: Scanner, ctx: ScanContext):
        self.scanner = scanner
        self.ctx = ctx

    def run(self) -> List[Finding]:
        findings = []

        findings += self._test_unauthenticated_api_access()
        findings += self._test_graphql()
        findings += self._test_mass_assignment()
        findings += self._test_api_versioning()

        self.ctx.mark_complete("api")
        return findings

    def _test_unauthenticated_api_access(self) -> List[Finding]:
        """Probe common API endpoints without auth."""
        findings = []
        base = self.scanner.get_base_domain()

        endpoints_to_test = REST_API_PATHS.copy()

        # Add discovered endpoints
        for ep in self.ctx.endpoints:
            if "/api/" in ep and ep not in endpoints_to_test:
                endpoints_to_test.append(ep)

        for path in endpoints_to_test[:30]:
            url = urljoin(base, path) if not path.startswith("http") else path
            resp = self.scanner.get(url)

            if not resp or resp.status_code not in (200,):
                continue

            # Check if response looks like real data
            if resp.is_json():
                try:
                    data = json.loads(resp.body)
                    if isinstance(data, list) and len(data) > 0:
                        # Array of objects = likely data exposure
                        f = Finding(
                            type=FindingType.UNAUTHENTICATED_API,
                            severity=Severity.HIGH,
                            title=f"Unauthenticated API returns data array",
                            url=url,
                            description=f"API endpoint returns {len(data)} records without authentication.",
                            evidence=f"Response: {resp.body[:400]}",
                            module="api",
                            metadata={"record_count": len(data)},
                        )
                        findings.append(f)
                        self.ctx.add_finding(f)
                        self.ctx.set_flag("unauthenticated_access", True)

                    elif isinstance(data, dict):
                        sensitive_keys = [
                            "email", "phone", "password", "token", "secret",
                            "key", "api_key", "users", "accounts",
                        ]
                        found_sensitive = [k for k in sensitive_keys if k in str(data).lower()]

                        if found_sensitive:
                            f = Finding(
                                type=FindingType.UNAUTHENTICATED_API,
                                severity=Severity.HIGH,
                                title=f"Unauthenticated API exposes sensitive fields",
                                url=url,
                                description=f"API returns data without auth. Sensitive fields detected: {found_sensitive}",
                                evidence=f"Response: {resp.body[:400]}",
                                module="api",
                                metadata={"sensitive_fields": found_sensitive},
                            )
                            findings.append(f)
                            self.ctx.add_finding(f)
                            self.ctx.set_flag("unauthenticated_access", True)

                except json.JSONDecodeError:
                    pass

        return findings

    def _test_graphql(self) -> List[Finding]:
        """Test GraphQL endpoints for introspection and common vulns."""
        findings = []

        if not self.ctx.get_flag("has_graphql"):
            return findings

        graphql_endpoints = [
            ep for ep in self.ctx.endpoints
            if "graphql" in ep.lower()
        ]

        base = self.scanner.get_base_domain()
        for path in ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql"]:
            url = urljoin(base, path)
            if url not in graphql_endpoints:
                graphql_endpoints.append(url)

        for endpoint in graphql_endpoints[:5]:
            # Test introspection
            resp = self.scanner.post(
                endpoint,
                json={"query": GRAPHQL_INTROSPECTION},
                headers={"Content-Type": "application/json"},
            )

            if not resp or resp.status_code != 200:
                continue

            try:
                data = json.loads(resp.body)
                if "data" in data and "__schema" in str(data):
                    # Extract type names
                    schema = data.get("data", {}).get("__schema", {})
                    types = [t.get("name") for t in schema.get("types", []) if t.get("name")]
                    sensitive_types = [
                        t for t in types
                        if any(k in t.lower() for k in ["user", "admin", "password", "secret", "key", "token"])
                    ]

                    f = Finding(
                        type=FindingType.GRAPHQL_INTROSPECTION,
                        severity=Severity.MEDIUM,
                        title="GraphQL introspection enabled",
                        url=endpoint,
                        description=f"GraphQL introspection is enabled. Full schema exposed with {len(types)} types.",
                        evidence=f"Types found: {types[:15]}\nSensitive types: {sensitive_types}",
                        module="api",
                        metadata={"type_count": len(types), "sensitive_types": sensitive_types},
                    )
                    findings.append(f)
                    self.ctx.add_finding(f)

                    # If sensitive types found, elevate severity
                    if sensitive_types:
                        f.severity = Severity.HIGH
                        f.description += f" Sensitive object types exposed: {sensitive_types}"

            except (json.JSONDecodeError, KeyError):
                pass

            # Test GraphQL batching abuse
            batch_query = [
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
            ]
            batch_resp = self.scanner.post(
                endpoint,
                json=batch_query,
                headers={"Content-Type": "application/json"},
            )
            if batch_resp and batch_resp.status_code == 200:
                try:
                    data = json.loads(batch_resp.body)
                    if isinstance(data, list):
                        f = Finding(
                            type=FindingType.RATE_LIMIT_MISSING,
                            severity=Severity.MEDIUM,
                            title="GraphQL batch queries enabled",
                            url=endpoint,
                            description="GraphQL accepts batched queries. Can be used to bypass rate limiting and brute force fields.",
                            evidence=f"Batch of 3 queries accepted, responses: {len(data)}",
                            module="api",
                        )
                        findings.append(f)
                        self.ctx.add_finding(f)
                except Exception:
                    pass

        return findings

    def _test_mass_assignment(self) -> List[Finding]:
        """Test registration/update endpoints for mass assignment."""
        findings = []

        if not self.ctx.get_flag("has_login"):
            return findings

        # Find registration and profile update endpoints
        target_endpoints = [
            ep for ep in self.ctx.endpoints
            if any(k in ep.lower() for k in ["register", "signup", "profile", "update", "account"])
        ]

        base = self.scanner.get_base_domain()
        for path in ["/api/register", "/api/v1/register", "/api/signup", "/api/user/update"]:
            url = urljoin(base, path)
            if url not in target_endpoints:
                target_endpoints.append(url)

        for endpoint in target_endpoints[:5]:
            # Send registration payload with privileged fields
            payload = {
                "username": "shadowtest_mass",
                "email": "shadowtest@shadowscan.io",
                "password": "ShadowTest123!",
            }

            # Add privileged fields
            for field in PRIVILEGED_FIELDS:
                payload[field] = True

            resp = self.scanner.post(
                endpoint,
                json=payload,
                headers={"Content-Type": "application/json"},
            )

            if not resp or resp.status_code not in (200, 201):
                continue

            # Check if privileged fields appear in response
            try:
                response_data = json.loads(resp.body)
                accepted_fields = [
                    f for f in PRIVILEGED_FIELDS
                    if f in str(response_data)
                ]

                if accepted_fields:
                    f = Finding(
                        type=FindingType.MASS_ASSIGNMENT,
                        severity=Severity.HIGH,
                        title=f"Mass assignment vulnerability",
                        url=endpoint,
                        description=f"Server accepted privileged fields in request payload: {accepted_fields}. Attacker may be able to escalate privileges.",
                        evidence=f"Sent fields: {list(payload.keys())}\nAccepted in response: {accepted_fields}\nResponse: {resp.body[:300]}",
                        module="api",
                        metadata={"accepted_fields": accepted_fields},
                    )
                    findings.append(f)
                    self.ctx.add_finding(f)

            except json.JSONDecodeError:
                pass

        return findings

    def _test_api_versioning(self) -> List[Finding]:
        """Check if older API versions are exposed and less secure."""
        findings = []
        base = self.scanner.get_base_domain()

        # Check multiple API versions
        versions = ["v1", "v2", "v3", "v4"]
        version_responses: Dict[str, int] = {}

        for v in versions:
            url = urljoin(base, f"/api/{v}/users")
            resp = self.scanner.get(url)
            if resp:
                version_responses[v] = resp.status_code

        # If newer version is 401 but older is 200, old version is less secure
        accessible_versions = [v for v, s in version_responses.items() if s == 200]
        restricted_versions = [v for v, s in version_responses.items() if s in (401, 403)]

        if accessible_versions and restricted_versions:
            f = Finding(
                type=FindingType.UNAUTHENTICATED_API,
                severity=Severity.HIGH,
                title="Older API version lacks authentication",
                url=urljoin(base, f"/api/{accessible_versions[0]}/"),
                description=f"API versions {accessible_versions} are accessible without auth, while {restricted_versions} require it. Old versions may expose sensitive data.",
                evidence=f"Version status codes: {version_responses}",
                module="api",
                metadata={"accessible": accessible_versions, "restricted": restricted_versions},
            )
            findings.append(f)
            self.ctx.add_finding(f)

        return findings
